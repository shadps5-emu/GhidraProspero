package prospero.util;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class ProsperoUtil {

	public static final String SCE_SPECIAL_SECTION = ".sce_special";
	// Marks a program this extension loaded.
	public static final String PROGRAM_PROPERTY = "prospero";

    private ProsperoUtil() {
    }

	public static boolean isProsperoProgram(Program program) {
		if (getSpecialBlock(program) != null) {
			return true;
		}
		return program.getUsrPropertyManager().getVoidPropertyMap(PROGRAM_PROPERTY) != null;
	}

	public static boolean isProsperoKernel(Program program) {
		if (isProsperoProgram(program)) {
			// this is lazy but will do for now
			return program.getMinAddress().getOffset() < 0;
		}
		return false;
	}

	public static MemoryBlock getSpecialBlock(Program program) {
		return program.getMemory().getBlock(SCE_SPECIAL_SECTION);
	}
}
