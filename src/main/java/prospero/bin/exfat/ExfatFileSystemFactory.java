package prospero.bin.exfat;

import ghidra.formats.gfilesystem.FSRL;

import prospero.bin.AbstractFileSystemFactory;

public class ExfatFileSystemFactory extends AbstractFileSystemFactory<ExfatFileSystem> {

	@Override
	public int getBytesRequired() {
		return ExfatHeader.BOOT_SIGNATURE_OFFSET + 2;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return ExfatHeader.isExfat(startBytes);
	}

}
