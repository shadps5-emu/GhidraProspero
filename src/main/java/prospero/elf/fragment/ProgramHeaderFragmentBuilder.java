package prospero.elf.fragment;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.program.model.address.Address;

import prospero.elf.ProsperoElfProgramBuilder;

public final class ProgramHeaderFragmentBuilder extends FragmentBuilder {

	private final ElfProgramHeader phdr;
	private final String name;

	public ProgramHeaderFragmentBuilder(ElfLoadHelper helper, ElfProgramHeader phdr, int i) {
		super(helper);
		this.phdr = phdr;
		this.name = getProgramHeaderName(phdr, i);
	}

	@Override
	protected Address getStart() {
		return getHelper().getDefaultAddress(phdr.getVirtualAddress());
	}

	@Override
	protected long getSize() {
		return phdr.getMemorySize();
	}

	@Override
	protected String getName() {
		return name;
	}

	public static boolean canHandle(ElfProgramHeader phdr) {
		switch (phdr.getType()) {
			case ElfProgramHeaderConstants.PT_GNU_EH_FRAME:
			case ElfProgramHeaderConstants.PT_DYNAMIC:
				return false;
			default:
				return true;
		}
	}

	private static String getProgramHeaderName(ElfProgramHeader phdr, int i) {
		return ProsperoElfProgramBuilder.getSegmentName(phdr, i);
	}

}
