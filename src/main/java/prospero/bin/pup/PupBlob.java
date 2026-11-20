package prospero.bin.pup;

import java.io.*;
import java.util.*;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.*;

import prospero.bin.FileInfoProvider;

final class PupBlob implements FileInfoProvider {

	private static final long INFO_MASK = 0x1;
	private static final long COMPRESSED_MASK = 0x8;
	private static final long BLOCKED_MASK = 0x800;
	private static final int DIGEST_SIZE = 32;
	private static final int EXTENT_SIZE = 8;

	private final BinaryReader reader;
	private final int index;
	private final long flags;
	private final long offset;
	private final long fileSize;
	private final long memorySize;
	private PupBlob info;
	private String fileName;

	PupBlob(BinaryReader reader, int index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.flags = reader.readNextLong();
		this.offset = reader.readNextLong();
		this.fileSize = reader.readNextLong();
		this.memorySize = reader.readNextLong();
	}

	int getIndex() {
		return index;
	}

	long getID() {
		return flags >>> 20;
	}

	long getOffset() {
		return offset;
	}

	long getFileSize() {
		return fileSize;
	}

	@Override
	public long getSize() {
		return memorySize;
	}

	boolean isInfo() {
		return (flags & INFO_MASK) != 0;
	}

	boolean isCompressed() {
		return (flags & COMPRESSED_MASK) != 0;
	}

	boolean isBlocked() {
		return (flags & BLOCKED_MASK) != 0;
	}

	long getBlockSize() {
		return 1L << (((flags >>> 12) & 0xF) + 12);
	}

	void setInfo(PupBlob info) {
		this.info = info;
	}

	byte[] getData() throws IOException {
		return reader.readByteArray(offset, (int) fileSize);
	}

	@Override
	public InputStream getInputStream() throws IOException {
		if (isCompressed() && isBlocked()) {
			if (info == null) {
				throw new IOException(
					"PUP entry " + index + " is blocked and compressed but has no block table");
			}
			return new SequenceInputStream(new BlockStreams());
		}
		InputStream is = reader.getByteProvider().getInputStream(offset);
		if (isCompressed()) {
			is = new InflaterInputStream(is);
		}
		return is;
	}

	/** The decoded blocks of a blocked, compressed entry, one stream each. */
	private final class BlockStreams implements Enumeration<InputStream> {

		private final int count;
		private final long[] extents;
		private int block = 0;

		BlockStreams() throws IOException {
			long blockSize = getBlockSize();
			this.count = (int) ((memorySize + blockSize - 1) / blockSize);
			long tableSize = (long) count * (DIGEST_SIZE + EXTENT_SIZE);
			if (info.getFileSize() < tableSize) {
				throw new IOException("PUP entry " + index + ": block table too small");
			}
			BinaryReader r = reader.clone(info.getOffset() + (long) count * DIGEST_SIZE);
			this.extents = new long[count * 2];
			for (int i = 0; i < count; i++) {
				extents[i * 2] = r.readNextUnsignedInt();
				extents[i * 2 + 1] = r.readNextUnsignedInt();
			}
		}

		@Override
		public boolean hasMoreElements() {
			return block < count;
		}

		@Override
		public InputStream nextElement() {
			long blockSize = getBlockSize();
			long length = Math.min(blockSize, memorySize - block * blockSize);
			long start = offset + extents[block * 2];
			long stored = extents[block * 2 + 1];
			block++;
			try {
				InputStream is = new ByteProviderWrapper(reader.getByteProvider(), start,
					offset + fileSize - start).getInputStream(0);
				if (stored >= length) {
					return new BoundedStream(is, length);
				}
				// a fresh zlib stream per block; it ends by itself
				return new BoundedStream(new InflaterInputStream(is, new Inflater()), length);
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}
	}

	/** Returns at most {@code length} bytes of the wrapped stream. */
	private static final class BoundedStream extends FilterInputStream {

		private long remaining;

		BoundedStream(InputStream in, long length) {
			super(in);
			this.remaining = length;
		}

		@Override
		public int read() throws IOException {
			if (remaining <= 0) {
				return -1;
			}
			int b = super.read();
			if (b >= 0) {
				remaining--;
			}
			return b;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (remaining <= 0) {
				return -1;
			}
			int n = super.read(b, off, (int) Math.min(len, remaining));
			if (n > 0) {
				remaining -= n;
			}
			return n;
		}
	}

	@Override
	public ByteProvider getByteProvider() {
		try {
			return new InputStreamByteProvider(getInputStream(), getSize());
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	public String getFileName() {
		if (fileName == null) {
			fileName = makeFileName();
		}
		return fileName;
	}

	private String makeFileName() {
		int id = (int) getID();
		switch (id & 0xFFF) {
			case 0x004: return "mbr.bin";
			case 0x005: return "kernel.bin";
			case 0x00B: return "titania.bls";
			case 0x00E: return "eap_kbl.bin";
			case 0x010: return "emc_salina_c0.bls";
			case 0x012: return "usb_pdc_salina_c0.bls";
			case 0x103: return "oberon_sec_ldr_c0.bin";
			case 0x201: return "wlanbt.bin";
			case 0x203: return "ssd0.system_b";
			case 0x204: return "ssd0.system_ex_b";
			case 0x207: return "ssd0.preinst";
			case 0x7D0: return "bluray.bin";
			default: return String.format("entry_%d_0x%x%s", index, id, guessExtension());
		}
	}

	private String guessExtension() {
		byte[] head = new byte[16];
		try (InputStream is = getInputStream()) {
			int n = is.readNBytes(head, 0, head.length);
			head = Arrays.copyOf(head, n);
		} catch (IOException | UncheckedIOException e) {
			return ".bin";
		}
		String text = new String(head, java.nio.charset.StandardCharsets.ISO_8859_1);
		if (text.startsWith("<?xml")) {
			return ".xml";
		}
		if (text.startsWith("{")) {
			return ".json";
		}
		if (text.startsWith("PK\3\4")) {
			return ".zip";
		}
		if (text.startsWith("SLB2")) {
			return ".bls";
		}
		if (text.startsWith("T\u0014õî") || text.startsWith("O\u0015=\u001D")) {
			return ".self";
		}
		return ".bin";
	}
}
