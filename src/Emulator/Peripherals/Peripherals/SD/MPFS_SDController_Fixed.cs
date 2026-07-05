//
// Copyright (c) 2024 Antmicro (original MPFS_SDController)
// Copyright (c) 2026 Serma Safety & Security (SDMA fix for Hardsploit)
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
// Fixed replacement for the built-in SD.MPFS_SDController peripheral.
// Root cause: the built-in controller defers TransferComplete to the next
// sync point (ExecuteInNearestSyncedState), but firmware polls SRS12 within
// the same quantum and never sees the completion bit.
//
// Key fixes:
// 1. DMA transfers and TransferComplete are set SYNCHRONOUSLY
// 2. CommandComplete is set before data transfer (so firmware's else-if
//    chain processes them in the correct order)
// 3. SRS14 (Signal Enable) is properly wired to the InterruptManager
//

using System;
using System.Collections.Generic;
using System.Linq;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Utilities;

namespace Antmicro.Renode.Peripherals.SD
{
    public class MPFS_SDController_Fixed : NullRegistrationPointPeripheralContainer<SDCard>,
        IDoubleWordPeripheral,
        IWordPeripheral,
        IBytePeripheral,
        IKnownSize,
        IProvidesRegisterCollection<DoubleWordRegisterCollection>
    {
        public MPFS_SDController_Fixed(IMachine machine) : base(machine)
        {
            sysbus = machine.GetSystemBus(this);
            IRQ = new GPIO();
            WakeupIRQ = new GPIO();
            internalBuffer = new Queue<byte>();
            responseFields = new uint[4];

            RegistersCollection = new DoubleWordRegisterCollection(this);
            DefineRegisters();

            this.Log(LogLevel.Warning, "MPFS_SDController_Fixed instantiated, Size=0x{0:X}", Size);
        }

        public uint ReadDoubleWord(long offset)
        {
            var result = RegistersCollection.Read(offset);
            return result;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            // Intercept SRS08 (Data Buffer Port) writes for PIO
            if(offset == 0x220)
            {
                // PIO write: collect data into buffer, write to card when block complete
                for(int i = 0; i < 4; i++)
                {
                    internalBuffer.Enqueue((byte)(value >> (i * 8)));
                }
                uint blockSize = blockSizeCountReg & 0xFFF;
                if(blockSize == 0) blockSize = 512;
                if(internalBuffer.Count >= (int)blockSize)
                {
                    var sdCard = RegisteredPeripheral;
                    if(sdCard != null)
                    {
                        var data = internalBuffer.ToArray();
                        internalBuffer.Clear();
                        sdCard.WriteData(data);
                    }
                    SetInterruptBit(InterruptTransferComplete);
                }
                return;
            }
            RegistersCollection.Write(offset, value);
        }

        public ushort ReadWord(long offset)
        {
            // SRS03 readback: return cached values for Transfer Mode / Command
            if(offset == 0x20C) return (ushort)transferModeReg;
            if(offset == 0x20E) return (ushort)commandRegUpper;

            // Default: extract the correct half from the 32-bit register
            var full = ReadDoubleWord(offset & ~0x3L);
            return (ushort)((offset & 0x2) != 0 ? (full >> 16) : full);
        }

        public void WriteWord(long offset, ushort value)
        {

            // Special handling for SRS03 (Transfer Mode + Command)
            // Per SDHCI spec: writing Transfer Mode (0x0C / offset 0x20C) just stores the value.
            // Writing Command (0x0E / offset 0x20E) triggers command execution.
            // U-Boot writes these as two separate 16-bit writes.
            if(offset == 0x20C)  // Lower half = Transfer Mode only
            {
                transferModeReg = value;
                return;  // Do NOT trigger command execution
            }
            if(offset == 0x20E)  // Upper half = Command → triggers execution
            {
                commandRegUpper = value;
                ExecuteCommand();
                return;
            }

            // Default: read-modify-write for all other registers
            var aligned = offset & ~0x3L;
            var full = RegistersCollection.Read(aligned);
            if((offset & 0x2) != 0)
            {
                full = (full & 0x0000FFFF) | ((uint)value << 16);
            }
            else
            {
                full = (full & 0xFFFF0000) | value;
            }
            WriteDoubleWord(aligned, full);
        }

        public byte ReadByte(long offset)
        {
            var full = ReadDoubleWord(offset & ~0x3L);
            return (byte)(full >> (int)((offset & 0x3) * 8));
        }

        public void WriteByte(long offset, byte value)
        {
            var aligned = offset & ~0x3L;
            var full = RegistersCollection.Read(aligned);
            var shift = (int)((offset & 0x3) * 8);
            full = (full & ~(0xFFu << shift)) | ((uint)value << shift);
            WriteDoubleWord(aligned, full);
        }

        public override void Reset()
        {
            RegistersCollection.Reset();
            internalBuffer.Clear();
            Array.Clear(responseFields, 0, responseFields.Length);
            interruptStatus = 0;
            statusEnable = 0;
            signalEnable = 0;
            pioBytesReadInBlock = 0;
            adma2Enabled = false;
            use64BitDma = false;
            admaDescriptorSize = 16;
            IRQ.Unset();
        }

        public long Size => 0x2000;

        public DoubleWordRegisterCollection RegistersCollection { get; }

        [IrqProvider]
        public GPIO IRQ { get; }

        public GPIO WakeupIRQ { get; }

        // =====================================================================
        // Interrupt management
        // =====================================================================

        private void SetInterruptBit(uint bit)
        {
            interruptStatus |= bit;
            UpdateIRQ();
        }

        private void UpdateIRQ()
        {
            // IRQ is asserted when any enabled status bit has a matching signal enable
            var active = interruptStatus & statusEnable & signalEnable;
            IRQ.Set(active != 0);
        }

        // =====================================================================
        // SD card command processing
        // =====================================================================

        private void ExecuteCommand()
        {
            var sdCard = RegisteredPeripheral;
            if(sdCard == null)
            {
                this.Log(LogLevel.Warning, "Command issued but no SD card attached");
                return;
            }

            uint cmdIndex = (commandRegUpper >> 8) & 0x3F;
            uint argument = argumentRegister;

            // Send command to the SD card model
            var response = sdCard.HandleCommand(cmdIndex, argument);
            var responseBytes = response.AsByteArray();

            // Fill response registers (SRS04-SRS07)
            // Response type from SRS03 bits [17:16] (in commandRegUpper bits [1:0])
            uint respType = commandRegUpper & 0x3;
            Array.Clear(responseFields, 0, 4);

            if(respType == 1 && responseBytes.Length >= 16)
            {
                // R2 (136-bit response) for CMD2/CMD9
                // SDCard model returns 16 bytes LSB-first: byte[0]=CSD[7:0], byte[15]=CSD[127:120]
                // Cadence SD4HC strips the 8-bit CRC+end from the wire response, so:
                //   SRS04[31:0] = CSD[39:8]   = {byte[4], byte[3], byte[2], byte[1]}
                //   SRS05[31:0] = CSD[71:40]  = {byte[8], byte[7], byte[6], byte[5]}
                //   SRS06[31:0] = CSD[103:72] = {byte[12], byte[11], byte[10], byte[9]}
                //   SRS07[23:0] = CSD[127:104]= {byte[15], byte[14], byte[13]}
                // byte[0] = CSD[7:0] is dropped (CRC equivalent in register space)
                responseFields[0] = (uint)(
                    (responseBytes[4] << 24) |
                    (responseBytes[3] << 16) |
                    (responseBytes[2] << 8)  |
                    (responseBytes[1]));
                responseFields[1] = (uint)(
                    (responseBytes[8] << 24) |
                    (responseBytes[7] << 16) |
                    (responseBytes[6] << 8)  |
                    (responseBytes[5]));
                responseFields[2] = (uint)(
                    (responseBytes[12] << 24) |
                    (responseBytes[11] << 16) |
                    (responseBytes[10] << 8) |
                    (responseBytes[9]));
                responseFields[3] = (uint)(
                    (responseBytes[15] << 16) |
                    (responseBytes[14] << 8)  |
                    (responseBytes[13]));

            }
            else
            {
                // R1/R3/R6/R7 (48-bit): simple little-endian fill
                for(int i = 0; i < Math.Min(responseBytes.Length, 16); i++)
                {
                    responseFields[i / 4] |= (uint)responseBytes[i] << ((i % 4) * 8);
                }
            }

            // Fix CMD13: SDCard model may report Programming state (7) after writes.
            // In emulation writes complete instantly — override to Transfer (4) so
            // the kernel's __mmc_poll_for_busy sees the card as ready.
            if(cmdIndex == 13)
            {
                uint statusWord = responseFields[0];
                uint cardState = (statusWord >> 9) & 0xF;
                if(cardState == 7) // Programming → Transfer
                {
                    responseFields[0] = (statusWord & ~(0xFu << 9)) | (4u << 9);
                }
            }

            // Set CommandComplete
            SetInterruptBit(InterruptCommandComplete);

            // Check response type for R1b (busy) — bits [1:0] of commandRegUpper = 11
            // R1b commands (CMD7, CMD12, CMD28, CMD29, CMD38) have a busy signal on DAT0.
            // U-Boot's sdhci_send_command waits for SDHCI_INT_DATA_END (bit 1) for these.
            // Since we complete instantly, set TransferComplete for R1b responses.
            uint respBits = commandRegUpper & 0x3;
            if(respBits == 3)  // R1b = response length 48 bits with busy
            {
                SetInterruptBit(InterruptTransferComplete);
            }

            // Check if this command has data
            bool dataPresent = (commandRegUpper & (1 << 5)) != 0;
            if(!dataPresent)
            {
                return;
            }

            // Data transfer direction: bit 4 of TRANSFER MODE register (not command register!)
            // SDHCI spec: Transfer Mode Register bit 4 = 1 for read, 0 for write
            bool isRead = (transferModeReg & (1 << 4)) != 0;
            bool dmaEnabled = (transferModeReg & 0x01) != 0;
            uint blockSize = blockSizeCountReg & 0xFFF;
            uint blockCount = (blockSizeCountReg >> 16) & 0xFFFF;

            if(blockSize == 0)
            {
                blockSize = 512;
            }
            if(blockCount == 0)
            {
                blockCount = 1;
            }

            uint totalBytes = blockCount * blockSize;


            // Auto-CMD support: Transfer Mode register bits [3:2]
            // 0=disabled, 1=Auto CMD12, 2=Auto CMD23
            // NOTE: Auto-CMD23 causes SDCard model to enter Programming state
            // and get stuck. The SDCard model doesn't need CMD23 for our pre-read
            // approach, so we skip it. Auto-CMD12 is also not needed since we
            // handle transfer completion synchronously.
            // uint autoCmdMode = (transferModeReg >> 2) & 0x3;

            if(isRead)
            {
                // Some commands have special data methods in the SDCard model
                byte[] specialData = null;
                if(cmdIndex == 6)  // CMD6: SWITCH_FUNC — 64-byte status
                {
                    specialData = sdCard.ReadSwitchFunctionStatusRegister();
                }

                if(dmaEnabled && adma2Enabled)
                {
                    if(specialData != null)
                    {
                        // CMD6 with ADMA2: write special data to first descriptor's target
                        ReadCardWithData(specialData, dmaEnabled);
                    }
                    else
                    {
                        ProcessAdma2Descriptors(true, sdCard);
                    }
                }
                else if(specialData != null)
                {
                    ReadCardWithData(specialData, dmaEnabled);
                }
                else
                {
                    ReadCard(sdCard, totalBytes, dmaEnabled);
                }
            }
            else
            {
                if(dmaEnabled && adma2Enabled)
                {
                    ProcessAdma2Descriptors(false, sdCard);
                }
                else
                {
                    WriteCard(sdCard, totalBytes, dmaEnabled);
                }
            }

            // Auto CMD12 disabled — see note above about SDCard model state machine
        }

        private void ReadCardWithData(byte[] data, bool dmaEnabled)
        {
            // Clear stale PIO data before enqueuing new data
            internalBuffer.Clear();

            if(dmaEnabled)
            {
                ulong dmaAddr = ((ulong)dmaAddrHigh << 32) | dmaAddrLow;
                sysbus.WriteBytes(data, dmaAddr);
                SetInterruptBit(InterruptTransferComplete);
            }
            else
            {
                foreach(var b in data)
                {
                    internalBuffer.Enqueue(b);
                }
                // Small single-block special reads (CMD6 etc.) — set both flags
                pioBlockSize = data.Length > 0 ? data.Length : 512;
                pioBytesReadInBlock = 0;
                SetInterruptBit(InterruptBufferReadReady);
                SetInterruptBit(InterruptTransferComplete);
            }
        }

        private void ReadCard(SDCard sdCard, uint totalBytes, bool dmaEnabled)
        {
            var data = sdCard.ReadData(totalBytes);
            internalBuffer.Clear();

            if(dmaEnabled)
            {
                // SDMA: write data directly to system bus at the DMA address
                ulong dmaAddr = ((ulong)dmaAddrHigh << 32) | dmaAddrLow;
                sysbus.WriteBytes(data, dmaAddr);

                // Set TransferComplete SYNCHRONOUSLY (the key fix!)
                SetInterruptBit(InterruptTransferComplete);
            }
            else
            {
                // PIO: enqueue data to internal buffer
                foreach(var b in data)
                {
                    internalBuffer.Enqueue(b);
                }
                // Track the block size for per-block BufferReadReady signaling
                pioBlockSize = (int)(blockSizeCountReg & 0xFFF);
                if(pioBlockSize == 0) pioBlockSize = 512;
                pioBytesReadInBlock = 0;

                // Signal first block ready — do NOT set TransferComplete yet.
                // U-Boot's SDHCI driver reads one block at a time, checking
                // INT_STATUS between blocks. TransferComplete must only be
                // set after ALL blocks are consumed from the buffer.
                SetInterruptBit(InterruptBufferReadReady);
            }
        }

        private void WriteCard(SDCard sdCard, uint totalBytes, bool dmaEnabled)
        {
            if(dmaEnabled)
            {
                // SDMA: read data from system bus at the DMA address
                ulong dmaAddr = ((ulong)dmaAddrHigh << 32) | dmaAddrLow;
                var data = sysbus.ReadBytes(dmaAddr, (int)totalBytes);
                sdCard.WriteData(data);
                SetInterruptBit(InterruptTransferComplete);
            }
            else
            {
                // PIO: signal BufferWriteReady, data will come through SRS08 writes
                SetInterruptBit(InterruptBufferWriteReady);
            }
        }

        private void ProcessAdma2Descriptors(bool isRead, SDCard sdCard)
        {
            ulong descAddr = ((ulong)dmaAddrHigh << 32) | dmaAddrLow;
            int maxDescriptors = 512;
            int totalTransferred = 0;
            int descCount = 0;

            // For reads: pre-read ALL data from the SD card upfront based on the
            // block count from the command. This ensures the card model's internal
            // position advances correctly regardless of how descriptors split the data.
            uint blockSize = blockSizeCountReg & 0xFFF;
            uint blockCount = (blockSizeCountReg >> 16) & 0xFFFF;
            if(blockSize == 0) blockSize = 512;
            if(blockCount == 0) blockCount = 1;
            uint totalBytes = blockCount * blockSize;

            byte[] readBuffer = null;
            int readOffset = 0;
            if(isRead)
            {
                readBuffer = sdCard.ReadData(totalBytes);
            }


            for(int i = 0; i < maxDescriptors; i++)
            {
                // Read descriptor from guest memory
                byte[] descBytes = sysbus.ReadBytes(descAddr, admaDescriptorSize);

                ushort cmd = (ushort)(descBytes[0] | (descBytes[1] << 8));
                ushort len = (ushort)(descBytes[2] | (descBytes[3] << 8));
                uint addrLo = (uint)(descBytes[4] | (descBytes[5] << 8) |
                                    (descBytes[6] << 16) | (descBytes[7] << 24));
                uint addrHi = 0;
                if(admaDescriptorSize >= 12)
                {
                    addrHi = (uint)(descBytes[8] | (descBytes[9] << 8) |
                                   (descBytes[10] << 16) | (descBytes[11] << 24));
                }

                bool valid = (cmd & 0x01) != 0;
                bool end = (cmd & 0x02) != 0;
                bool interrupt = (cmd & 0x04) != 0;
                uint action = (uint)(cmd >> 4) & 0x3;

                uint xferLen = (len == 0) ? 65536u : (uint)len;
                ulong bufAddr = ((ulong)addrHi << 32) | addrLo;

                if(!valid)
                {
                    descAddr += (ulong)admaDescriptorSize;
                    continue;
                }

                if(action == 2) // TRAN — Transfer data
                {
                    if(isRead)
                    {
                        // Copy from pre-read buffer to guest memory
                        int copyLen = (int)Math.Min(xferLen, (uint)(readBuffer.Length - readOffset));
                        if(copyLen > 0)
                        {
                            var chunk = new byte[copyLen];
                            Array.Copy(readBuffer, readOffset, chunk, 0, copyLen);
                            sysbus.WriteBytes(chunk, bufAddr);
                            readOffset += copyLen;
                        }
                    }
                    else
                    {
                        var data = sysbus.ReadBytes(bufAddr, (int)xferLen);
                        sdCard.WriteData(data);
                    }
                    totalTransferred += (int)xferLen;
                    descCount++;
                }
                // action == 0: NOP — skip
                // action == 1: reserved/LINK — skip

                if(interrupt)
                {
                    SetInterruptBit(InterruptDmaInterrupt);
                }

                if(end)
                {
                    break;
                }

                descAddr += (ulong)admaDescriptorSize;
            }


            SetInterruptBit(InterruptTransferComplete);
            SetInterruptBit(InterruptDmaInterrupt);  // DMA_END — kernel checks this for ADMA transfers
        }

        private uint ReadBuffer()
        {
            uint value = 0;
            for(int i = 0; i < 4 && internalBuffer.Count > 0; i++)
            {
                value |= (uint)internalBuffer.Dequeue() << (i * 8);
                pioBytesReadInBlock++;
            }

            // Per-block signaling: after each block is fully consumed
            if(pioBytesReadInBlock >= pioBlockSize)
            {
                pioBytesReadInBlock = 0;
                if(internalBuffer.Count == 0)
                {
                    // Last block consumed — signal transfer complete
                    SetInterruptBit(InterruptTransferComplete);
                }
                else
                {
                    // More blocks remain — signal next block ready
                    SetInterruptBit(InterruptBufferReadReady);
                }
            }

            return value;
        }

        // =====================================================================
        // Register definitions (Cadence SD4HC register layout)
        // =====================================================================

        private void DefineRegisters()
        {
            // ----- HRS00: General Information / Software Reset -----
            // Bit 0: Software reset (self-clearing — HSS writes 1, polls until 0)
            Registers.HRS00.Define(this, 0x00000000)
                .WithFlag(0, FieldMode.Read | FieldMode.Write, name: "SWR",
                    writeCallback: (_, val) =>
                    {
                        if(val)
                        {
                            // Software reset requested — immediately clear (self-clearing)
                            Reset();
                        }
                    },
                    valueProviderCallback: _ => false)  // Always reads as 0 (reset complete)
                .WithValueField(1, 31, name: "HRS00_RSVD");

            // ----- HRS04: PHY Access Port -----
            // U-Boot Cadence driver writes PHY config, sets WR bit (24), polls for ACK bit (26).
            // We auto-set ACK whenever WR is written.
            Registers.HRS04.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "PHY_ACCESS",
                    writeCallback: (_, val) =>
                    {
                        hrs04Value = (uint)val;
                        // If WR bit (24) is set, immediately set ACK bit (26)
                        if((hrs04Value & (1u << 24)) != 0)
                        {
                            hrs04Value |= (1u << 26);  // ACK
                        }
                        else
                        {
                            hrs04Value &= ~(1u << 26);  // Clear ACK when WR cleared
                        }
                    },
                    valueProviderCallback: _ => hrs04Value);

            // ----- HRS06: eMMC Control -----
            // U-Boot Cadence driver sets SD/eMMC mode. Just store the value.
            Registers.HRS06.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "EMMC_CTRL",
                    writeCallback: (_, val) => { hrs06Value = (uint)val; },
                    valueProviderCallback: _ => hrs06Value);

            // ----- SRS00: SDMA System Address / Argument 2 -----
            Registers.SRS00.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "SDMA_ARG2",
                    writeCallback: (_, val) => { dmaAddrLow = (uint)val; },
                    valueProviderCallback: _ => dmaAddrLow);

            // ----- SRS01: Block Size / Block Count -----
            Registers.SRS01.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "BLOCK_SIZE_COUNT",
                    writeCallback: (_, val) => { blockSizeCountReg = (uint)val; },
                    valueProviderCallback: _ => blockSizeCountReg);

            // ----- SRS02: Argument 1 -----
            Registers.SRS02.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "ARGUMENT1",
                    writeCallback: (_, val) => { argumentRegister = (uint)val; },
                    valueProviderCallback: _ => argumentRegister);

            // ----- SRS03: Transfer Mode / Command -----
            // Lower 16 bits: Transfer Mode (written first)
            // Upper 16 bits: Command (triggers execution)
            // The Cadence controller treats this as a single 32-bit write
            Registers.SRS03.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "XFER_MODE_CMD",
                    writeCallback: (_, val) =>
                    {
                        transferModeReg = (uint)(val & 0xFFFF);
                        commandRegUpper = (uint)((val >> 16) & 0xFFFF);
                        ExecuteCommand();
                    },
                    valueProviderCallback: _ => transferModeReg | (commandRegUpper << 16));

            // ----- SRS04-SRS07: Response Registers -----
            Registers.SRS04.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "RESPONSE0",
                    valueProviderCallback: _ => responseFields[0]);

            Registers.SRS05.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "RESPONSE1",
                    valueProviderCallback: _ => responseFields[1]);

            Registers.SRS06.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "RESPONSE2",
                    valueProviderCallback: _ => responseFields[2]);

            Registers.SRS07.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "RESPONSE3",
                    valueProviderCallback: _ => responseFields[3]);

            // ----- SRS08: Data Buffer Port -----
            // IMPORTANT: Use FieldMode.Read for the valueProvider to prevent
            // the register framework from calling ReadBuffer() during writes.
            // PIO writes are handled separately via WriteDoubleWord override.
            Registers.SRS08.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "DATA_PORT",
                    valueProviderCallback: _ => ReadBuffer());

            // ----- SRS09: Present State Register -----
            Registers.SRS09.Define(this, 0x00000000)
                .WithFlag(0, FieldMode.Read, name: "CMD_INHIBIT_CMD",
                    valueProviderCallback: _ => false)  // never busy
                .WithFlag(1, FieldMode.Read, name: "CMD_INHIBIT_DAT",
                    valueProviderCallback: _ => false)  // never busy
                .WithFlag(2, FieldMode.Read, name: "DAT_LINE_ACTIVE",
                    valueProviderCallback: _ => false)
                .WithReservedBits(3, 5)
                .WithFlag(8, FieldMode.Read, name: "WRITE_TRANS_ACTIVE",
                    valueProviderCallback: _ => false)
                .WithFlag(9, FieldMode.Read, name: "READ_TRANS_ACTIVE",
                    valueProviderCallback: _ => false)
                .WithFlag(10, FieldMode.Read, name: "BUFF_WRITE_EN",
                    valueProviderCallback: _ => true)   // always ready
                .WithFlag(11, FieldMode.Read, name: "BUFF_READ_EN",
                    valueProviderCallback: _ => internalBuffer.Count >= 4)
                .WithReservedBits(12, 4)
                .WithFlag(16, FieldMode.Read, name: "CARD_INSERTED",
                    valueProviderCallback: _ => RegisteredPeripheral != null)
                .WithFlag(17, FieldMode.Read, name: "CARD_STATE_STABLE",
                    valueProviderCallback: _ => true)
                .WithFlag(18, FieldMode.Read, name: "CARD_DETECT_PIN",
                    valueProviderCallback: _ => RegisteredPeripheral != null)
                .WithFlag(19, FieldMode.Read, name: "WRITE_PROTECT",
                    valueProviderCallback: _ => false)  // not write-protected
                .WithFlag(20, FieldMode.Read, name: "DAT0_SIGNAL_LEVEL",
                    valueProviderCallback: _ => true)   // DAT0 high = not busy
                .WithFlag(21, FieldMode.Read, name: "DAT1_SIGNAL_LEVEL",
                    valueProviderCallback: _ => true)
                .WithFlag(22, FieldMode.Read, name: "DAT2_SIGNAL_LEVEL",
                    valueProviderCallback: _ => true)
                .WithFlag(23, FieldMode.Read, name: "DAT3_SIGNAL_LEVEL",
                    valueProviderCallback: _ => true)
                .WithFlag(24, FieldMode.Read, name: "CMD_SIGNAL_LEVEL",
                    valueProviderCallback: _ => true)
                .WithReservedBits(25, 7);

            // ----- SRS10: Host Control 1 / Power / Block Gap / Wakeup -----
            // Bits [4:3] = DMA Select: 00=SDMA, 01=ADMA2-32, 10=ADMA2-64, 11=ADMA2-64v4
            Registers.SRS10.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "HOST_CTRL1",
                    writeCallback: (_, val) =>
                    {
                        hostControl1 = (uint)val;
                        uint dmaSelect = (hostControl1 >> 3) & 0x3;
                        adma2Enabled = (dmaSelect >= 1);
                        // Set descriptor size based on DMA Select when not using v4_mode
                        if(!use64BitDma)
                        {
                            if(dmaSelect == 1) admaDescriptorSize = 8;   // ADMA2 32-bit
                            else if(dmaSelect == 2) admaDescriptorSize = 12; // ADMA2 64-bit (v3)
                            else if(dmaSelect == 3) admaDescriptorSize = 12; // ADMA2 64-bit
                        }
                    },
                    valueProviderCallback: _ => hostControl1);

            // ----- SRS11: Clock Control / Timeout / Software Reset -----
            // Bits [2:0]: Internal Clock Enable, Internal Clock Stable, SD Clock Enable
            // Bits [15:8]: Clock Divider
            // Bits [19:16]: Data Timeout Counter
            // Bit 24: Software Reset All (self-clearing)
            // Bit 25: Software Reset CMD line (self-clearing)
            // Bit 26: Software Reset DAT line (self-clearing)
            Registers.SRS11.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "CLK_CTRL",
                    writeCallback: (_, val) =>
                    {
                        clockControl = (uint)val;
                        // Auto-set internal clock stable when internal clock is enabled
                        if((clockControl & 0x01) != 0)
                        {
                            clockControl |= 0x02; // INT_CLOCK_STABLE
                        }
                        // Auto-clear software reset bits (self-clearing)
                        // Bit 24: RESET_ALL, Bit 25: RESET_CMD, Bit 26: RESET_DAT
                        clockControl &= ~0x07000000u;
                    },
                    valueProviderCallback: _ => clockControl);

            // ----- SRS12: Normal/Error Interrupt Status (Write-1-to-Clear) -----
            Registers.SRS12.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "INT_STATUS",
                    valueProviderCallback: _ => interruptStatus,
                    writeCallback: (_, val) =>
                    {
                        // Write-1-to-Clear: clear bits that are written as 1
                        interruptStatus &= ~(uint)val;
                        UpdateIRQ();
                    });

            // ----- SRS13: Normal/Error Status Enable -----
            Registers.SRS13.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "STATUS_ENABLE",
                    writeCallback: (_, val) =>
                    {
                        statusEnable = (uint)val;
                        UpdateIRQ();
                    },
                    valueProviderCallback: _ => statusEnable);

            // ----- SRS14: Normal/Error Signal Enable -----
            Registers.SRS14.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "SIGNAL_ENABLE",
                    writeCallback: (_, val) =>
                    {
                        signalEnable = (uint)val;
                        UpdateIRQ();
                    },
                    valueProviderCallback: _ => signalEnable);

            // ----- SRS15: Host Control 2 -----
            // This is a 32-bit register at 0x23C. The kernel writes HOST_CONTROL2
            // as a 16-bit value to offset 0x23E (upper half). So bit 12 (V4_MODE)
            // and bit 13 (64BIT_ADDR) of the 16-bit HOST_CONTROL2 end up at
            // bits 28 and 29 of the 32-bit SRS15 register.
            Registers.SRS15.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "HOST_CTRL2",
                    writeCallback: (_, val) =>
                    {
                        hostControl2 = (uint)val;
                        // Check both possible bit positions:
                        // - Bit 29: 64BIT_ADDR when written as 16-bit to upper half (0x23E)
                        // - Bit 13: 64BIT_ADDR when written as 32-bit to 0x23C
                        use64BitDma = ((hostControl2 & (1u << 29)) != 0) ||
                                      ((hostControl2 & (1u << 13)) != 0);
                        bool v4Mode = ((hostControl2 & (1u << 28)) != 0) ||
                                      ((hostControl2 & (1u << 12)) != 0);
                        // v4_mode uses 16-byte descriptors; non-v4 uses 12-byte
                        admaDescriptorSize = (use64BitDma || v4Mode) ? 16 : 12;
                    },
                    valueProviderCallback: _ => hostControl2);

            // ----- SRS16: Capabilities 1 -----
            // Report: 3.3V, SDMA, ADMA2, 64-bit bus, 512 max block, 128MHz base clock
            Registers.SRS16.Define(this, 0x11F88000)
                .WithValueField(0, 32, FieldMode.Read, name: "CAPABILITIES1",
                    valueProviderCallback: _ => 0x11F88000u);
            // Bit 19: ADMA2 support = 1
            // Bit 22: SDMA support = 1
            // Bit 24: 3.3V support = 1
            // Bit 25: 3.0V support = 1
            // Bit 26: 1.8V support = 1
            // Bit 28: 64-bit system bus = 1
            // Bits 15-8: Base Clock Freq = 0x80 = 128 MHz

            // ----- SRS17: Capabilities 2 -----
            Registers.SRS17.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "CAPABILITIES2",
                    valueProviderCallback: _ => 0x00000000u);

            // ----- SRS at offset 0x2FC: Host Controller Version -----
            // Standard SDHCI offset 0xFE (16-bit) = 0xFC (32-bit aligned)
            // Cadence: SRS base (0x200) + 0xFC = 0x2FC
            // Reports SDHCI spec v4.10 (value 4) for full v4_mode + ADMA2 64-bit support
            Registers.HostVersion.Define(this, 0x00040000)
                .WithValueField(0, 32, FieldMode.Read, name: "HOST_VERSION",
                    valueProviderCallback: _ => 0x00040000u);
            // Bits [31:16] = 0x0004 → Spec Version 4.10 (read via 16-bit at 0x2FE)
            // Bits [15:0] = 0x0000 → Slot Interrupt Status (not used)

            // ----- SRS21: ADMA Error Status -----
            // Kernel reads this after ADMA errors. Return 0 = no error.
            Registers.SRS21.Define(this, 0x00000000)
                .WithValueField(0, 32, FieldMode.Read, name: "ADMA_ERROR_STATUS",
                    valueProviderCallback: _ => 0u);

            // ----- SRS22: DMA Address Low -----
            Registers.SRS22.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "DMA_ADDR_LOW",
                    writeCallback: (_, val) => { dmaAddrLow = (uint)val; },
                    valueProviderCallback: _ => dmaAddrLow);

            // ----- SRS23: DMA Address High -----
            Registers.SRS23.Define(this, 0x00000000)
                .WithValueField(0, 32, name: "DMA_ADDR_HIGH",
                    writeCallback: (_, val) => { dmaAddrHigh = (uint)val; },
                    valueProviderCallback: _ => dmaAddrHigh);
        }

        // =====================================================================
        // Fields
        // =====================================================================

        private readonly IBusController sysbus;
        private readonly Queue<byte> internalBuffer;
        private readonly uint[] responseFields;

        // Register backing fields
        private uint blockSizeCountReg;
        private uint argumentRegister;
        private uint transferModeReg;
        private uint commandRegUpper;
        private uint hostControl1;
        private uint clockControl;
        private uint hostControl2;
        private uint dmaAddrLow;
        private uint dmaAddrHigh;
        private uint hrs04Value;
        private uint hrs06Value;

        // PIO multi-block read tracking
        private int pioBlockSize = 512;
        private int pioBytesReadInBlock;

        // ADMA2 state
        private bool adma2Enabled;
        private bool use64BitDma;
        private int admaDescriptorSize = 16;

        // Interrupt state
        private uint interruptStatus;
        private uint statusEnable;
        private uint signalEnable;

        // SRS12 bit positions (from SD Host Controller spec / Cadence SD4HC)
        private const uint InterruptCommandComplete   = 0x00000001;
        private const uint InterruptTransferComplete   = 0x00000002;
        private const uint InterruptBlockGapEvent      = 0x00000004;
        private const uint InterruptDmaInterrupt       = 0x00000008;
        private const uint InterruptBufferWriteReady   = 0x00000010;
        private const uint InterruptBufferReadReady    = 0x00000020;
        private const uint InterruptCardInsertion      = 0x00000040;
        private const uint InterruptCardRemoval        = 0x00000080;
        private const uint InterruptErrorInterrupt     = 0x00008000;

        // Cadence SD4HC register offsets
        private enum Registers : long
        {
            HRS00 = 0x000,
            HRS04 = 0x010,  // PHY access port (Cadence-specific)
            HRS06 = 0x018,  // eMMC control (Cadence-specific)
            SRS00 = 0x200,  // SDMA System Address / Argument 2
            SRS01 = 0x204,  // Block Size / Block Count
            SRS02 = 0x208,  // Argument 1
            SRS03 = 0x20C,  // Transfer Mode / Command
            SRS04 = 0x210,  // Response 0
            SRS05 = 0x214,  // Response 1
            SRS06 = 0x218,  // Response 2
            SRS07 = 0x21C,  // Response 3
            SRS08 = 0x220,  // Data Buffer Port
            SRS09 = 0x224,  // Present State
            SRS10 = 0x228,  // Host Control 1 / Power / Block Gap
            SRS11 = 0x22C,  // Clock Control / Timeout / Reset
            SRS12 = 0x230,  // Normal/Error Interrupt Status
            SRS13 = 0x234,  // Normal/Error Status Enable
            SRS14 = 0x238,  // Normal/Error Signal Enable
            SRS15 = 0x23C,  // Host Control 2
            SRS16 = 0x240,  // Capabilities 1
            SRS17 = 0x244,  // Capabilities 2
            SRS21 = 0x254,  // ADMA Error Status
            HostVersion = 0x2FC, // SDHCI Host Controller Version (std offset 0xFC)
            SRS22 = 0x258,  // ADMA/SDMA System Address Low
            SRS23 = 0x25C,  // ADMA/SDMA System Address High
        }
    }
}
