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
package ghidra.app.util.bin.format.coff.relocation;

import ghidra.app.util.bin.format.coff.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.NotFoundException;

public class I960_CoffRelocationHandler extends CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		System.out.println("canRelocate:  "+fileHeader.getMachine());
		return (fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_I960ROMAGIC ||
			fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_I960RWMAGIC);
	}

	@Override
	public void relocate(Program program, Address address, Symbol symbol,
			CoffRelocation relocation) throws MemoryAccessException, NotFoundException {
		System.out.println("relocate i960: "+address+" "+symbol.getName()+" "+relocation.getAddress()+", type="+relocation.getType());
		int addend = program.getMemory().getInt(address);

		switch (relocation.getType()) {
			case IMAGE_REL_I960_RELLONG:
			case IMAGE_REL_I960_IPRMED:
			case IMAGE_REL_I960_OPTCALL:			    
			default:
				throw new NotFoundException();
		}
	}
    
	/**
	 * 32-bit absolute relocation
	 */
	public final static short IMAGE_REL_I960_RELLONG = 0x0011;
    
	/**
	 * 24-bit ip-relative relocation
	 */
	public final static short IMAGE_REL_I960_IPRMED = 0x0019;
    
	/**
	 *  32-bit optimizable call
	 */
	public final static short IMAGE_REL_I960_OPTCALL = 0x001b;

}
