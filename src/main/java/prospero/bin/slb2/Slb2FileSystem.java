package prospero.bin.slb2;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.task.TaskMonitor;

import prospero.bin.AbstractFileSystem;
import prospero.bin.FileSystemHeader;
import prospero.bin.FirmwareImageHeader;

@FileSystemInfo(type = "slb2", description = "SLB2 Container", priority = FileSystemInfo.PRIORITY_LOW, factory = Slb2FileSystemFactory.class)
public class Slb2FileSystem extends AbstractFileSystem<Slb2Entry> {

	public Slb2FileSystem(FSRLRoot fsrl, ByteProvider provider) {
		super(fsrl, provider);
	}

	@Override
	protected FileSystemHeader<Slb2Entry> getHeader() throws IOException {
		return new Slb2Header(new BinaryReader(getProvider(), true));
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		Slb2Entry entry = getMetadata(file);
		if (entry == null) {
			return FileAttributes.EMPTY;
		}
		FileAttributes attrs = new FileAttributes();
		attrs.add(NAME_ATTR, file.getName());
		attrs.add(SIZE_ATTR, entry.getSize());
		attrs.add("Offset in container", String.format("0x%x", entry.getBlockIndex() * 512));
		try (InputStream is = entry.getByteProvider().getInputStream(0)) {
			FirmwareImageHeader.addAttributes(attrs, is, entry.getSize());
		}
		catch (IOException e) {
			// the attributes above are still shown
		}
		return attrs;
	}
}
