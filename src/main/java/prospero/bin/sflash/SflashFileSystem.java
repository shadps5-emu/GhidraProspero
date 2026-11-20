package prospero.bin.sflash;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

import prospero.bin.AbstractFileSystem;
import prospero.bin.FileSystemHeader;

@FileSystemInfo(type = "sflash", description = "Prospero SFLASH", priority = FileSystemInfo.PRIORITY_LOW, factory = SflashFileSystemFactory.class)
public class SflashFileSystem extends AbstractFileSystem<SflashEntry> {

	public SflashFileSystem(FSRLRoot fsrl, ByteProvider provider) {
		super(fsrl, provider);
	}

	@Override
	protected FileSystemHeader<SflashEntry> getHeader() throws IOException {
		return new SflashHeader(getProvider());
	}

}
