package prospero.bin.pup;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import prospero.bin.AbstractFileSystem;
import prospero.bin.FileSystemHeader;

@FileSystemInfo(type = "pup", description = "Update Package", priority = FileSystemInfo.PRIORITY_LOW, factory = PupFileSystemFactory.class)
public class PupFileSystem extends AbstractFileSystem<PupBlob> {

	public PupFileSystem(FSRLRoot fsrl, ByteProvider provider) {
		super(fsrl, provider);
	}

	@Override
	protected FileSystemHeader<PupBlob> getHeader() throws IOException {
		return new PupHeader(getProvider());
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		PupBlob entry = getMetadata(file);
		if (entry == null) {
			throw new IOException("Unknown file " + file);
		}
		return FileSystemService.getInstance().getDerivedByteProvider(
			getProvider().getFSRL(), file.getFSRL(), file.getName(), entry.getSize(),
			entry::getInputStream, monitor);
	}

}
