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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

class I960_CoffSymbol extends CoffSymbol {

	private short e_flags;
	private byte [] unused1;
	
	I960_CoffSymbol(BinaryReader reader, CoffFileHeader header) throws IOException {

		if (reader.peekNextInt() == 0) {//look up name in string table
			reader.readNextInt();//skip null
			int nameIndex = reader.readNextInt();//string table index
			int stringTableIndex =
				header.getSymbolTablePointer() +
					(header.getSymbolTableEntries() * I960_CoffConstants.SYMBOL_SIZEOF);
			e_name = reader.readAsciiString(stringTableIndex + nameIndex);
		}
		else {
			e_name = reader.readNextAsciiString(I960_CoffConstants.SYMBOL_NAME_LENGTH);
		}

		e_value = reader.readNextInt();
		e_scnum = reader.readNextShort();
		e_flags = reader.readNextShort();
		e_type = reader.readNextInt();
		e_sclass = reader.readNextByte();
		e_numaux = reader.readNextByte();
		unused1 = reader.readNextByteArray(2);

		for (int i = 0; i < e_numaux; ++i) {
			_auxiliarySymbols.add(I960_CoffSymbolAuxFactory.read(reader, this));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(getClass()), 0);
		struct.add(new ArrayDataType(ASCII, CoffConstants.SYMBOL_NAME_LENGTH, ASCII.getLength()),
			"e_name", null);
		struct.add(DWORD, "e_value", null);
		struct.add(WORD, "e_scnum", null);
		struct.add(WORD, "e_flags", null);
		struct.add(DWORD, "e_type", null);
		struct.add(BYTE, "e_sclass", null);
		struct.add(BYTE, "e_numaux", null);
		struct.add(WORD, "pad", null);
		return struct;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(getName());
		buffer.append(' ');
		buffer.append("Value=0x" + Long.toHexString(getValue()));
		buffer.append(' ');
		buffer.append(e_scnum);
		buffer.append(' ');
		buffer.append(e_type);
		buffer.append(' ');
		buffer.append(e_sclass);
		return buffer.toString();
	}
}
