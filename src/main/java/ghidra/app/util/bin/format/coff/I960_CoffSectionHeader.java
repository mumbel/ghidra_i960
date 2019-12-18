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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;


class I960_CoffSectionHeader extends CoffSectionHeader {

	I960_CoffSectionHeader(BinaryReader reader, CoffFileHeader header) throws IOException {
		_header = header;
		readName(reader);

		s_paddr = reader.readNextInt();
		s_vaddr = reader.readNextInt();
		s_size = reader.readNextInt();
		s_scnptr = reader.readNextInt();
		s_relptr = reader.readNextInt();
		s_lnnoptr = reader.readNextInt();
		s_nreloc = reader.readNextShort() & 0xffff;
		s_nlnno = reader.readNextShort() & 0xffff;
		s_flags = reader.readNextInt();

		reader.readNextInt(); // section alignment, currently unused

		s_reserved = 0;
		s_page = 0;
	}

	
	/**
	 * Returns the length of line number entries for this section.
	 * @return the length of line number entries for this section
	 */
	@Override
	public int getLineNumberLength() {
		return s_nlnno * I960_CoffConstants.LINENO_SIZEOF;
	}
	
	@Override
	protected void readName(BinaryReader reader) throws IOException {
		byte[] nameBytes = reader.readNextByteArray(I960_CoffConstants.SECTION_NAME_LENGTH);
		if (nameBytes[0] == 0 && nameBytes[1] == 0 && nameBytes[2] == 0 && nameBytes[3] == 0) {//if 1st 4 bytes are zero, then lookup name in string table

			DataConverter dc = reader.isLittleEndian() ? LittleEndianDataConverter.INSTANCE
					: BigEndianDataConverter.INSTANCE;
			int nameIndex = dc.getInt(nameBytes, 4);//string table index
			int stringTableIndex = _header.getSymbolTablePointer() +
				(_header.getSymbolTableEntries() * I960_CoffConstants.SYMBOL_SIZEOF);
			s_name = reader.readAsciiString(stringTableIndex + nameIndex);
		}
		else {
			s_name = (new String(nameBytes)).trim();
		}
	}
}
