package prospero.bin.exfat;

import java.io.*;
import java.time.*;
import java.util.*;

import ghidra.app.util.bin.*;

import prospero.bin.FileInfoProvider;

/** A file in an exFAT volume. */
final class ExfatEntry implements FileInfoProvider {

	private static final int ATTR_READ_ONLY = 0x01;
	private static final int ATTR_HIDDEN = 0x02;
	private static final int ATTR_SYSTEM = 0x04;
	private static final int ATTR_ARCHIVE = 0x20;

	private final ByteProvider provider;
	private final long imageLength;
	private final String path;
	private final int attributes;
	private final Date created;
	private final Date modified;
	private final Date accessed;
	private final long length;
	private final long validLength;
	private final long[] runs;

	ExfatEntry(ByteProvider provider, long imageLength, String path, int attributes, long created,
			long modified, long accessed, int created10ms, int modified10ms, byte createdUtc,
			byte modifiedUtc, byte accessedUtc, long length, long validLength, long[] runs) {
		this.provider = provider;
		this.imageLength = imageLength;
		this.path = path;
		this.attributes = attributes;
		this.created = toDate(created, created10ms, createdUtc);
		this.modified = toDate(modified, modified10ms, modifiedUtc);
		this.accessed = toDate(accessed, 0, accessedUtc);
		this.length = length;
		this.validLength = validLength;
		this.runs = runs;
	}

	/**
	 * An exFAT timestamp: a DOS date and time (2 s steps), a count of 10 ms to
	 * add, and the offset from UTC in 15 minute steps (bit 7: offset is valid).
	 */
	private static Date toDate(long stamp, int tenMs, byte utc) {
		if (stamp == 0) {
			return null;
		}
		try {
			LocalDateTime t = LocalDateTime.of((int) (stamp >>> 25) + 1980,
				(int) (stamp >>> 21) & 0xF, (int) (stamp >>> 16) & 0x1F,
				(int) (stamp >>> 11) & 0x1F, (int) (stamp >>> 5) & 0x3F,
				(int) (stamp & 0x1F) * 2).plusNanos(tenMs * 10_000_000L);
			ZoneOffset offset = ZoneOffset.UTC;
			if ((utc & 0x80) != 0) {
				int quarters = (byte) (utc << 1) >> 1;
				offset = ZoneOffset.ofTotalSeconds(quarters * 15 * 60);
			}
			return Date.from(t.toInstant(offset));
		}
		catch (DateTimeException e) {
			return null;
		}
	}

	@Override
	public String getFileName() {
		return path;
	}

	@Override
	public long getSize() {
		return length;
	}

	Date getCreated() {
		return created;
	}

	Date getModified() {
		return modified;
	}

	Date getAccessed() {
		return accessed;
	}

	String getAttributeNames() {
		List<String> names = new ArrayList<>();
		if ((attributes & ATTR_READ_ONLY) != 0) {
			names.add("read-only");
		}
		if ((attributes & ATTR_HIDDEN) != 0) {
			names.add("hidden");
		}
		if ((attributes & ATTR_SYSTEM) != 0) {
			names.add("system");
		}
		if ((attributes & ATTR_ARCHIVE) != 0) {
			names.add("archive");
		}
		return names.isEmpty() ? "none" : String.join(", ", names);
	}

	int getFragmentCount() {
		return runs.length / 2;
	}

	/** The file is one run in the image, all of it written, and the image holds it all. */
	boolean isContiguous() {
		return runs.length == 2 && validLength == length &&
			runs[0] + runs[1] <= imageLength;
	}

	long getStart() {
		return runs.length == 0 ? 0 : runs[0];
	}

	@Override
	public InputStream getInputStream() throws IOException {
		List<InputStream> parts = new ArrayList<>();
		long left = validLength;
		for (int i = 0; i < runs.length && left > 0; i += 2) {
			long n = Math.min(runs[i + 1], left);
			if (runs[i] + n > imageLength) {
				throw new IOException(path + " lies past the end of the exFAT image");
			}
			parts.add(new ByteProviderWrapper(provider, runs[i], n).getInputStream(0));
			left -= n;
		}
		// beyond the valid data length a file reads as zeros
		parts.add(new ZeroStream(length - validLength));
		return new SequenceInputStream(Collections.enumeration(parts));
	}

	@Override
	public ByteProvider getByteProvider() {
		try {
			return new InputStreamByteProvider(getInputStream(), getSize());
		}
		catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	/** {@code length} zero bytes. */
	private static final class ZeroStream extends InputStream {

		private long remaining;

		ZeroStream(long length) {
			this.remaining = length;
		}

		@Override
		public int read() {
			if (remaining <= 0) {
				return -1;
			}
			remaining--;
			return 0;
		}

		@Override
		public int read(byte[] b, int off, int len) {
			if (remaining <= 0) {
				return -1;
			}
			int n = (int) Math.min(len, remaining);
			Arrays.fill(b, off, off + n, (byte) 0);
			remaining -= n;
			return n;
		}
	}
}
