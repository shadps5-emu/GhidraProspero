package prospero.bin.exfat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

import prospero.bin.BinStructure;
import prospero.bin.FileSystemHeader;

/**
 * An exFAT volume: the boot sector, the FAT and every file in the directory
 * tree. ssd0.system_b and ssd0.system_ex_b in the PS5 PUP are exFAT images.
 * They end after the last cluster in use, so the volume can be larger than
 * the image.
 */
final class ExfatHeader extends BinStructure implements FileSystemHeader<ExfatEntry> {

	static final int SIGNATURE_OFFSET = 3;
	static final byte[] SIGNATURE = "EXFAT   ".getBytes(StandardCharsets.US_ASCII);
	static final int BOOT_SIGNATURE_OFFSET = 510;
	static final int BOOT_SIGNATURE = 0xAA55;

	private static final int ENTRY_SIZE = 32;
	private static final int TYPE_END = 0x00;
	private static final int TYPE_FILE = 0x85;
	private static final int TYPE_STREAM = 0xC0;
	private static final int TYPE_NAME = 0xC1;
	private static final int ATTR_DIRECTORY = 0x10;
	private static final int STREAM_NO_FAT_CHAIN = 0x2;
	private static final int NAME_CHARS = 15;
	private static final long FIRST_CLUSTER = 2;
	private static final long LAST_CLUSTER = 0xFFFFFFF6L;

	private final BinaryReader reader;
	private final long fatOffset;
	private final long heapOffset;
	private final long clusterCount;
	private final long rootCluster;
	private final int clusterSize;
	private final List<ExfatEntry> files = new ArrayList<>();

	ExfatHeader(ByteProvider provider) throws IOException {
		this.reader = new BinaryReader(provider, true);
		if (!isExfat(reader.readByteArray(0, BOOT_SIGNATURE_OFFSET + 2))) {
			throw new IOException("Not an exFAT volume");
		}
		long fatSector = reader.readUnsignedInt(80);
		long heapSector = reader.readUnsignedInt(88);
		this.clusterCount = reader.readUnsignedInt(92);
		this.rootCluster = reader.readUnsignedInt(96);
		int bytesPerSectorShift = reader.readUnsignedByte(108);
		int sectorsPerClusterShift = reader.readUnsignedByte(109);
		if (bytesPerSectorShift < 9 || bytesPerSectorShift > 12 ||
			bytesPerSectorShift + sectorsPerClusterShift > 25) {
			throw new IOException("exFAT: bad sector or cluster size");
		}
		this.fatOffset = fatSector << bytesPerSectorShift;
		this.heapOffset = heapSector << bytesPerSectorShift;
		this.clusterSize = 1 << (bytesPerSectorShift + sectorsPerClusterShift);
		readDirectory(chain(rootCluster, -1, false), "", new HashSet<>());
	}

	static boolean isExfat(byte[] boot) {
		if (boot.length < BOOT_SIGNATURE_OFFSET + 2) {
			return false;
		}
		byte[] sig = Arrays.copyOfRange(boot, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE.length);
		int bootSig = (boot[BOOT_SIGNATURE_OFFSET] & 0xFF) | (boot[BOOT_SIGNATURE_OFFSET + 1] & 0xFF) << 8;
		return Arrays.equals(sig, SIGNATURE) && bootSig == BOOT_SIGNATURE;
	}

	/**
	 * The clusters of a cluster chain as runs of consecutive clusters: start
	 * offset in the image and length in bytes, two longs per run.
	 *
	 * @param first the first cluster
	 * @param length the chain's length in bytes, or -1 to follow the FAT to its end
	 * @param noFatChain the clusters are consecutive and the FAT is not used
	 */
	private long[] chain(long first, long length, boolean noFatChain) throws IOException {
		if (length == 0) {
			return new long[0];
		}
		long max = length < 0 ? clusterCount : (length + clusterSize - 1) / clusterSize;
		List<Long> runs = new ArrayList<>();
		long cluster = first;
		long count = 0;
		while (count < max) {
			if (cluster < FIRST_CLUSTER || cluster >= FIRST_CLUSTER + clusterCount) {
				if (length < 0 && cluster > LAST_CLUSTER) {
					break; // end of chain
				}
				throw new IOException("exFAT: bad cluster " + cluster);
			}
			long offset = heapOffset + (cluster - FIRST_CLUSTER) * clusterSize;
			int last = runs.size() - 2;
			if (last >= 0 && runs.get(last) + runs.get(last + 1) == offset) {
				runs.set(last + 1, runs.get(last + 1) + clusterSize);
			}
			else {
				runs.add(offset);
				runs.add((long) clusterSize);
			}
			count++;
			cluster = noFatChain ? cluster + 1 : reader.readUnsignedInt(fatOffset + cluster * 4);
		}
		if (length >= 0) {
			// the last cluster is only partly used
			int last = runs.size() - 1;
			runs.set(last, runs.get(last) - (count * clusterSize - length));
		}
		long[] result = new long[runs.size()];
		for (int i = 0; i < result.length; i++) {
			result[i] = runs.get(i);
		}
		return result;
	}

	private byte[] read(long[] runs) throws IOException {
		long total = 0;
		for (int i = 1; i < runs.length; i += 2) {
			total += runs[i];
		}
		if (total > Integer.MAX_VALUE) {
			throw new IOException("exFAT: directory too large");
		}
		byte[] data = new byte[(int) total];
		int pos = 0;
		for (int i = 0; i < runs.length; i += 2) {
			byte[] part = reader.readByteArray(runs[i], (int) runs[i + 1]);
			System.arraycopy(part, 0, data, pos, part.length);
			pos += part.length;
		}
		return data;
	}

	private void readDirectory(long[] runs, String path, Set<Long> seen) throws IOException {
		if (runs.length == 0 || !seen.add(runs[0])) {
			return;
		}
		byte[] dir = read(runs);
		BinaryReader r = new BinaryReader(new ByteArrayProvider(dir), true);
		for (int pos = 0; pos + ENTRY_SIZE <= dir.length;) {
			int type = r.readUnsignedByte(pos);
			if (type == TYPE_END) {
				break;
			}
			if (type != TYPE_FILE) {
				pos += ENTRY_SIZE;
				continue;
			}
			int secondary = r.readUnsignedByte(pos + 1);
			int stream = pos + ENTRY_SIZE;
			if (secondary < 2 || stream + secondary * ENTRY_SIZE > dir.length ||
				r.readUnsignedByte(stream) != TYPE_STREAM) {
				pos += ENTRY_SIZE;
				continue;
			}
			int attributes = r.readUnsignedShort(pos + 4);
			int flags = r.readUnsignedByte(stream + 1);
			int nameLength = r.readUnsignedByte(stream + 3);
			long validLength = r.readLong(stream + 8);
			long cluster = r.readUnsignedInt(stream + 20);
			long length = r.readLong(stream + 24);
			StringBuilder name = new StringBuilder();
			for (int i = 2; i <= secondary; i++) {
				int e = pos + i * ENTRY_SIZE;
				if (r.readUnsignedByte(e) == TYPE_NAME) {
					name.append(new String(dir, e + 2, NAME_CHARS * 2, StandardCharsets.UTF_16LE));
				}
			}
			name.setLength(Math.min(nameLength, name.length()));
			String full = path + "/" + name;
			boolean noFatChain = (flags & STREAM_NO_FAT_CHAIN) != 0;
			if (length < 0 || validLength < 0 || validLength > length) {
				throw new IOException("exFAT: bad size for " + full);
			}
			long[] data = chain(cluster, length, noFatChain);
			if ((attributes & ATTR_DIRECTORY) != 0) {
				readDirectory(data, full, seen);
			}
			else {
				files.add(new ExfatEntry(reader.getByteProvider(), full.substring(1), attributes,
					r.readUnsignedInt(pos + 8), r.readUnsignedInt(pos + 12),
					r.readUnsignedInt(pos + 16), r.readUnsignedByte(pos + 20),
					r.readUnsignedByte(pos + 21), r.readByte(pos + 22), r.readByte(pos + 23),
					r.readByte(pos + 24), length, validLength, data));
			}
			pos += (secondary + 1) * ENTRY_SIZE;
		}
	}

	@Override
	public Iterator<ExfatEntry> iterator() {
		return files.iterator();
	}
}
