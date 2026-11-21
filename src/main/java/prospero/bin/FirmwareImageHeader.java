package prospero.bin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

public final class FirmwareImageHeader {

	private static final byte[] MAGIC = { 0x1D, 0x33, 0x47, 0x77 };
	private static final int BODY_SIZE = 0x08;
	private static final int HEADER_SIZE = 0x0C;
	private static final int VERSION = 0x4B0;
	private static final int VERSION_MAX = 0x20;
	private static final int VERSION_MIN = 8;

	private FirmwareImageHeader() {
	}

	public static void addAttributes(FileAttributes attrs, InputStream is, long size)
			throws IOException {
		byte[] h = is.readNBytes((int) Math.min(size, VERSION + VERSION_MAX));
		if (h.length < HEADER_SIZE + 4 || !Arrays.equals(h, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
			return;
		}
		long body = u32(h, BODY_SIZE);
		long header = u32(h, HEADER_SIZE);
		attrs.add("Image bytes 4-7", HexFormat.ofDelimiter(" ").formatHex(h, 4, 8));
		attrs.add("Image header size", hex(header));
		attrs.add("Image body size", hex(body));
		if (header + body != size) {
			attrs.add("Image size check", "header + body = " + hex(header + body) +
				", image is " + hex(size));
		}
		String version = version(h);
		if (version != null) {
			attrs.add("Image version", version);
		}
	}

	private static String version(byte[] h) {
		if (h.length < VERSION + VERSION_MIN) {
			return null;
		}
		int end = VERSION;
		while (end < h.length && h[end] != 0) {
			if (h[end] < 0x20 || h[end] > 0x7E) {
				return null;
			}
			end++;
		}
		if (end - VERSION < VERSION_MIN) {
			return null;
		}
		return new String(h, VERSION, end - VERSION, StandardCharsets.US_ASCII);
	}

	private static long u32(byte[] b, int off) {
		return (b[off] & 0xFFL) | (b[off + 1] & 0xFFL) << 8 | (b[off + 2] & 0xFFL) << 16 |
			(b[off + 3] & 0xFFL) << 24;
	}

	private static String hex(long v) {
		return String.format("0x%x (%d)", v, v);
	}
}
