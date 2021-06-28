/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package naomi;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class NaomiLoader extends AbstractLibrarySupportLoader {
	
	private static class NaomiHeader {
		@SuppressWarnings("unused")
		String label;
		@SuppressWarnings("unused")
		private int addr;
		private NaomiHeader(String label, int addr) {
			this.label = label;
			this.addr = addr;
		}
	}
	
	@SuppressWarnings("unused")
	private static class ExecLoadEntry {
		private int rom_offset;
		private int load_addr;
		private int lenght;
		private ExecLoadEntry(int i, int j, int k) {
			this.setRom_offset(rom_offset);
			this.setLoad_addr(load_addr);
			this.setLenght(lenght);
		}
		@SuppressWarnings("unused")
		public int getRom_offset() {
			return rom_offset;
		}
		public void setRom_offset(int rom_offset) {
			this.rom_offset = rom_offset;
		}
		@SuppressWarnings("unused")
		public int getLoad_addr() {
			return load_addr;
		}
		public void setLoad_addr(int load_addr) {
			this.load_addr = load_addr;
		}
		@SuppressWarnings("unused")
		public int getLenght() {
			return lenght;
		}
		public void setLenght(int lenght) {
			this.lenght = lenght;
		}
	}
	
	/*
	 * GameHeader class, this is definitely a complex array of things, including other classes as loading
	 * address references and arrays of address to copy data into 
	 */
	@SuppressWarnings("unused")
	private static final NaomiHeader[] GAMEHeader = {
			new NaomiHeader("SYSTEM_DESCRIPTION", 0x000), //Should be NAOMI always
			new NaomiHeader("PUBLISHER", 0x010),
			new NaomiHeader("Japan_Region_Name", 0x030),
			new NaomiHeader("USA_Region_Name", 0x050),
			new NaomiHeader("Export_Region_Name", 0x070),
			new NaomiHeader("Korea_Region_Name", 0x090),
			new NaomiHeader("Australia_Region_Name", 0x0B0),
			new NaomiHeader("Debug_Region_Name_1", 0x0D0),
			new NaomiHeader("Debug_Region_Name_2", 0x0F0),
			new NaomiHeader("Debug_Region_Name_3", 0x110),
			new NaomiHeader("Manufactured_Year", 0x130),
			new NaomiHeader("Manufactured_Month", 0x132),
			new NaomiHeader("Manufactured_Day", 0x133),
			new NaomiHeader("Serial_Number", 0x134),
			new NaomiHeader("ROM_Mode_Flag", 0x138), //Non-zero value specifies that ROM board offsets should be OR'd with 0x20000000.
			new NaomiHeader("G1_BUS_Flag", 0x13A), //Non-zero value specifies that the below G1 BUS register values should be used.
			new NaomiHeader("SB_G1RRC", 0x13C),
			new NaomiHeader("SB_G1RWC", 0x140),
			new NaomiHeader("SB_G1FRC", 0x144),
			new NaomiHeader("SB_G1FWC", 0x148),
			new NaomiHeader("SB_G1CRC", 0x14C),
			new NaomiHeader("SB_G1CWC", 0x150),
			new NaomiHeader("SB_G1GDRC", 0x154),
			new NaomiHeader("SB_G1GDWC", 0x158),
			new NaomiHeader("M2_M4_ROM_Checksums", 0x15C), //132 bytes of M2/M4-type ROM checksums.
			new NaomiHeader("EPROM_Init_Values", 0x1E0),
			new NaomiHeader("Credit_Information_Label_1", 0x260),
			new NaomiHeader("Credit_Information_Label_2", 0x280),
			new NaomiHeader("Credit_Information_Label_3", 0x2A0),
			new NaomiHeader("Credit_Information_Label_4", 0x2C0),
			new NaomiHeader("Credit_Information_Label_5", 0x2E0),
			new NaomiHeader("Credit_Information_Label_6", 0x300),
			new NaomiHeader("Credit_Information_Label_7", 0x320),
			new NaomiHeader("Credit_Information_Label_8", 0x340),
			new NaomiHeader("BIOS_Check_EEPROM", 0x42C),
			new NaomiHeader("M1_Type_Checksums", 0x42E),
			new NaomiHeader("Unusual_Padding", 0x4B8),
			new NaomiHeader("Header_Encryption", 0x4FF), //If it's on means header is encrypted starting at offset 0x010
	};
	
	private static class SH4MemoryRegion {
		private String name;
		private int addr;
		private int size;
		private boolean read;
		private boolean write;
		private boolean execute;
		private SH4MemoryRegion(String name, int addr, int size, boolean read, boolean write, boolean execute) {
			this.setName(name);
			this.setAddr(addr);
			this.setSize(size);
			this.setRead(read);
			this.setWrite(write);
			this.setExecute(execute);
		}
		@SuppressWarnings("unused")
		public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		@SuppressWarnings("unused")
		public int getAddr() {
			return addr;
		}
		public void setAddr(int addr) {
			this.addr = addr;
		}
		@SuppressWarnings("unused")
		public int getSize() {
			return size;
		}
		public void setSize(int size) {
			this.size = size;
		}
		@SuppressWarnings("unused")
		public boolean isExecute() {
			return execute;
		}
		public void setExecute(boolean execute) {
			this.execute = execute;
		}
		@SuppressWarnings("unused")
		public boolean isRead() {
			return read;
		}
		public void setRead(boolean read) {
			this.read = read;
		}
		@SuppressWarnings("unused")
		public boolean isWrite() {
			return write;
		}
		public void setWrite(boolean write) {
			this.write = write;
		}
	}
	
	// Areas partially taken from the amazing doc at http://archives.dcemulation.org/munkeechuff/hardware/Memory.html
	private static final SH4MemoryRegion[] SH4MemRegs = {
			new SH4MemoryRegion("GameHeader", 0x00000000, 0x00001000, true, false, false),
			new SH4MemoryRegion("BootROM", 0x00001000, 0x001FFFFF, true, true, true),
			//new SH4MemoryRegion("FlashROM", 0x00200000, 0x0023FFFF, true, true, true),
			new SH4MemoryRegion("HardwareRegisters", 0x00240000, 0x03FFFFFF, true, true, false),
			new SH4MemoryRegion("VideoMemory", 0x04000000, 0x047FFFFF, true, true, false),
			//new SH4MemoryRegion("NotUsed1", 0x04800000, 0x07FFFFFF, true, true, false),
			//new SH4MemoryRegion("NotUsed2", 0x08000000, 0x0BFFFFFF, true, true, false),
			new SH4MemoryRegion("SystemMemory", 0x0C000000, 0x0CFFFFFF, true, true, true),
			new SH4MemoryRegion("TileAccelerator", 0x10000000, 0x107FFFFF, false, true, false),
			new SH4MemoryRegion("TextureMemory", 0x10800000, 0x11FFFFFF, false, true, false),
			new SH4MemoryRegion("G2Devices", 0x14000000, 0x17FFFFFF, true, true, false),
			new SH4MemoryRegion("SH4ControlRegisters", 0x1C000000, 0x1FFFFFFF, true, true, false),
	};

	@Override
	public String getName() {

		return "SEGA NAOMI Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// We are returning SH4 Little Endian, as well that's how NAOMI boots
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), true));

		return loadSpecs;
	}

	/*
	 * 
	 */
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		InputStream inStream = provider.getInputStream(0);
		Memory mem = program.getMemory();
		// Loop to create the memory blocks
		for(SH4MemoryRegion memregion: SH4MemRegs) {
			var message = "Loading SH4 memory region " + memregion.name;
			monitor.setMessage(message);
			try {
				//memregion.name, api.toAddr(memregion.addr), memregion.size, false
//				api.createMemoryBlock(memregion.name, api.toAddr(memregion.addr), provider.readBytes(memregion.addr, memregion.size), false);
				mem.createInitializedBlock(memregion.name, api.toAddr(memregion.addr), inStream, memregion.size, monitor, false);
				api.createLabel(api.toAddr(memregion.addr),memregion.name.replace(" ","_"),false);

			} catch (LockException e) {
				e.printStackTrace();
			} catch (DuplicateNameException e) {
				e.printStackTrace();
			} catch (MemoryConflictException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		MemoryBlock gh_block = mem.getBlock("GameHeader");
		MemoryBlock sysmem_block = mem.getBlock("SystemMemory");
		byte b[];
		gh_block.setComment("AUTO COMMENT IT WORKED");
		InputStream ghStream = gh_block.getData();
		List<ExecLoadEntry> loaders = new ArrayList<ExecLoadEntry>();
		try {
			int ELMarker = 0xFFFFFFFF;
			int Addr = 0x360;
			// Variables for the ExecLoadEntry objects.
			int rom_offset;
			int load_addr;
			int data_length;
			ByteBuffer wrapped;
			do {
				// we pull load addies, 3 vales, easier to pull on line right not make it cute later.
				// ROM Offset value
				//System.out.println(String.format("Loading data from address 0x%08X", Addr));
				log.appendMsg(String.format("Loading data from address 0x%08X", Addr));
				b = api.getBytes(api.toAddr(Addr), 4);
				wrapped = ByteBuffer.wrap(b);
				rom_offset = Integer.reverseBytes(wrapped.getInt());
				System.out.println(String.format("0x%08X", rom_offset));
				
				Addr += 4;
				if(rom_offset == ELMarker)
					break;
				// Address to write it into
				//System.out.println(String.format("Loading data from address 0x%08X", Addr));
				log.appendMsg(String.format("Loading data from address 0x%08X", Addr));
				b = api.getBytes(api.toAddr(Addr), 4);
				wrapped = ByteBuffer.wrap(b);
				load_addr = Integer.reverseBytes(wrapped.getInt());
				System.out.println(String.format("0x%08X", load_addr));
				Addr += 4;
				if(load_addr == ELMarker)
					break;
				// Length of the data to copy
				//System.out.println(String.format("Loading data from address 0x%08X", Addr));
				log.appendMsg(String.format("Loading data from address 0x%08X", Addr));
				b = api.getBytes(api.toAddr(Addr), 4);
				wrapped = ByteBuffer.wrap(b);
				data_length = Integer.reverseBytes(wrapped.getInt());
				System.out.println(String.format("0x%08X", data_length));
				Addr += 4;
				if(data_length == ELMarker)
					break;
				// Create the object and add into the array
				ExecLoadEntry el = new ExecLoadEntry(rom_offset, load_addr, data_length);
				loaders.add(el);
				
				// Get the data and put it into the "correct" memory space
				log.appendMsg(String.format("Loading data from ROM offset 0x%08X into memory segment 0x%08X", rom_offset, load_addr));
				b = api.getBytes(api.toAddr(rom_offset), data_length);
				api.setBytes(api.toAddr(load_addr), b);
			} while(true);
			
			
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//gh_block.getBytes(api.toAddr(0x306), b, 0, 4);
		
		
	
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
