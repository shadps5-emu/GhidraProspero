package prospero.bin.pup;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

import prospero.bin.BinStructure;
import prospero.bin.FileSystemHeader;

final class PupHeader extends BinStructure implements FileSystemHeader<PupBlob> {
	static final byte[] MAGIC = new byte[] {
		(byte) 0x54, (byte) 0x14, (byte) 0xF5, (byte) 0xEE
	};

	private final BinaryReader reader;
	private final int version;
	private final int mode;
	private final int endian;
	private final int flags;
	private final int content;
	private final int product;
	private final int headerSize;
	private final int metaSize;
	private final long fileSize;
	private final int blobCount;
	private final int flags2;
	private final long blobStart;
	private final List<PupBlob> files;

	PupHeader(ByteProvider provider) throws IOException {
		this.reader = new BinaryReader(provider, true);
		// skip magic
		skipBytes(MAGIC.length);
		this.version = reader.readNextUnsignedByte();
		this.mode = reader.readNextUnsignedByte();
		this.endian = reader.readNextUnsignedByte();
		this.flags = reader.readNextUnsignedByte();
		this.content = reader.readNextUnsignedByte();
		this.product = reader.readNextUnsignedByte();
		// skip padding
		skipBytes(2);
		this.headerSize = reader.readNextUnsignedShort();
		this.metaSize = reader.readNextUnsignedShort();
		this.fileSize = reader.readNextLong();
		this.blobCount = reader.readNextUnsignedShort();
		this.flags2 = reader.readNextUnsignedShort();
		// skip padding
		skipBytes(4);
		this.blobStart = reader.getPointerIndex();
		this.files = readBlobs();
	}

	private List<PupBlob> readBlobs() throws IOException {
		List<PupBlob> all = new ArrayList<>(blobCount);
		reader.setPointerIndex(blobStart);
		for (int i = 0; i < blobCount; i++) {
			all.add(new PupBlob(reader, i));
		}
		List<PupBlob> result = new ArrayList<>();
		for (PupBlob blob : all) {
			if (!blob.isInfo()) {
				result.add(blob);
				continue;
			}
			long target = blob.getID();
			if (target < all.size()) {
				all.get((int) target).setInfo(blob);
			}
		}
		return result;
	}

	private void skipBytes(int n) {
		advanceReader(reader, n);
	}

	int getBlobCount() {
		return blobCount;
	}

	@Override
	public Iterator<PupBlob> iterator() {
		return files.iterator();
	}

	/**
	 * @return the reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * @return the version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @return the mode
	 */
	public int getMode() {
		return mode;
	}

	/**
	 * @return the endian
	 */
	public int getEndian() {
		return endian;
	}

	/**
	 * @return the flags
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * @return the content
	 */
	public int getContent() {
		return content;
	}

	/**
	 * @return the product
	 */
	public int getProduct() {
		return product;
	}

	/**
	 * @return the headerSize
	 */
	public int getHeaderSize() {
		return headerSize;
	}

	/**
	 * @return the metaSize
	 */
	public int getMetaSize() {
		return metaSize;
	}

	/**
	 * @return the fileSize
	 */
	public long getFileSize() {
		return fileSize;
	}

	/**
	 * @return the flags2
	 */
	public int getFlags2() {
		return flags2;
	}

	/**
	 * @return the blobStart
	 */
	public long getBlobStart() {
		return blobStart;
	}
}
