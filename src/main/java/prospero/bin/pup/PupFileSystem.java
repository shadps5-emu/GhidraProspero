package prospero.bin.pup;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import prospero.bin.AbstractFileSystem;
import prospero.bin.FileSystemHeader;
import prospero.bin.FirmwareImageHeader;

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

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		PupBlob entry = getMetadata(file);
		if (entry == null) {
			return FileAttributes.EMPTY;
		}
		FileAttributes attrs = new FileAttributes();
		attrs.add(NAME_ATTR, file.getName());
		attrs.add(SIZE_ATTR, entry.getSize());
		attrs.add("Stored size", entry.getFileSize());
		attrs.add("Entry index", entry.getIndex());
		attrs.add("Entry ID", String.format("0x%x", entry.getID()));
		attrs.add("Offset in PUP", String.format("0x%x", entry.getOffset()));
		attrs.add("Flags", String.format("0x%x: %s", entry.getFlags(), entry.getFlagNames()));
		if (entry.hasBlockTable()) {
			attrs.add("Block table", "entry " + entry.getBlockTable().getIndex());
		}
		try (InputStream is = entry.getInputStream()) {
			FirmwareImageHeader.addAttributes(attrs, is, entry.getSize());
		}
		catch (IOException | UncheckedIOException e) {
			// the attributes above are still shown
		}
		return attrs;
	}
}
