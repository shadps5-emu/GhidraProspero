package prospero.bin.exfat;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import prospero.bin.AbstractFileSystem;
import prospero.bin.FileSystemHeader;

@FileSystemInfo(type = "exfat", description = "exFAT Volume", priority = FileSystemInfo.PRIORITY_LOW, factory = ExfatFileSystemFactory.class)
public class ExfatFileSystem extends AbstractFileSystem<ExfatEntry> {

	public ExfatFileSystem(FSRLRoot fsrl, ByteProvider provider) {
		super(fsrl, provider);
	}

	@Override
	protected FileSystemHeader<ExfatEntry> getHeader() throws IOException {
		return new ExfatHeader(getProvider());
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ExfatEntry entry = getMetadata(file);
		if (entry == null) {
			throw new IOException("Unknown file " + file);
		}
		if (entry.isContiguous()) {
			return new ByteProviderWrapper(getProvider(), entry.getStart(), entry.getSize(),
				file.getFSRL());
		}
		return FileSystemService.getInstance().getDerivedByteProvider(
			getProvider().getFSRL(), file.getFSRL(), file.getName(), entry.getSize(),
			entry::getInputStream, monitor);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		ExfatEntry entry = getMetadata(file);
		if (entry == null) {
			return FileAttributes.EMPTY;
		}
		FileAttributes attrs = new FileAttributes();
		attrs.add(NAME_ATTR, file.getName());
		attrs.add(SIZE_ATTR, entry.getSize());
		if (entry.getCreated() != null) {
			attrs.add(CREATE_DATE_ATTR, entry.getCreated());
		}
		if (entry.getModified() != null) {
			attrs.add(MODIFIED_DATE_ATTR, entry.getModified());
		}
		if (entry.getAccessed() != null) {
			attrs.add(ACCESSED_DATE_ATTR, entry.getAccessed());
		}
		attrs.add("Attributes", entry.getAttributeNames());
		attrs.add("Fragments", entry.getFragmentCount());
		return attrs;
	}
}
