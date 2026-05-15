using System.ComponentModel;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace Fox.FileSystem;

public unsafe class EC1
{
    private static readonly uint[] DWXS = new uint[]{ 0x41441043, 0x11C22050, 0xD05608C3, 0x532C7319 };
    private const uint DWBlockSize = sizeof(uint);
    private const uint DWCount = 4;
    private const uint DWLoopMask = DWCount - 1;
    private const uint DWLoopCount = 5;
        
    public static void SEHeader(byte* data, ulong dataSize, uint unitSize)
    {
        uint* blockData = (uint*)data;
        
        for (ulong i = 0; i < dataSize / DWBlockSize; i++)
        {
            ulong byteIndex = i * DWBlockSize;
            ulong unitIndex = byteIndex / unitSize;
            
            blockData[i] ^= DWXS[(unitIndex + byteIndex / DWLoopCount) & DWLoopMask];
        }
    }

    private static readonly ulong[] QWXS = new ulong[]{ 0x65229958BB8ADEDB, 0x8812130208453206, 0x2C02F10C4C344955, 0xF38185834887F823 };
    private const uint QWBlockSize = sizeof(ulong);
    private const uint QWAlignMask = QWBlockSize - 1;
    private const uint QWCount = 4;
    private const uint QWLoopMask = QWCount - 1;
    private const uint QWLoopRate = 11;
    
    public static void SEContent(byte* data, uint dataSize, ulong startOffset, uint hash, bool forceSlow)
    {
        if (dataSize == 0)
            return;

        if (forceSlow)
        {
            for (uint i = 0; i < dataSize; i++)
            {
                ulong byteIndex = startOffset + i;
                ulong qwordIndex = byteIndex - (byteIndex & QWAlignMask);
                
                ulong key = QWXS[(hash + qwordIndex / QWLoopRate) & QWLoopMask];
                data[i] ^= ((byte*)&key)[byteIndex & QWAlignMask];
            }
        }
        else
        {
            ulong offset = startOffset;
            ulong end = (uint)startOffset + dataSize;

            // Fast path: process bytes in three stages
            // 1. Unaligned head: bytes until next 8-byte boundary
            ulong alignedStart = (offset + QWAlignMask) & ~QWAlignMask;

            if (alignedStart >= end)
            {
                // Region too small to hit an 8-byte boundary — just do byte-by-byte
                while (offset < end)
                {
                    ulong key = QWXS[(hash + offset / QWLoopRate) & QWLoopMask];
                    *data ^= ((byte*)&key)[offset & QWAlignMask];
                    data++;
                    offset++;
                }
                return;
            }

            // Head: partial bytes before alignment
            while (offset < alignedStart)
            {
                ulong key = QWXS[(hash + offset / QWLoopRate) & QWLoopMask];
                *data ^= ((byte*)&key)[offset & QWAlignMask];
                data++;
                offset++;
            }

            // 2. Aligned bulk: full 8-byte blocks
            ulong bulkCount = (end - alignedStart) / QWBlockSize;
            ulong* block = (ulong*)data;
            for (uint i = 0; i < bulkCount; i++, block++, offset += QWBlockSize)
            {
                *block ^= QWXS[(hash + offset / QWLoopRate) & QWLoopMask];
            }
            data = (byte*)block;

            // 3. Tail: remaining bytes after last full block
            while ((uint)offset < end)
            {
                ulong key = QWXS[(hash + offset / QWLoopRate) & QWLoopMask];
                *data ^= ((byte*)&key)[offset & QWAlignMask];
                data++;
                offset++;
            }
        }
    }
}

public unsafe class SecureQarFile : MountPoint
{
    public const uint Signature = 0x52415153; // SQAR
    
    [Flags]
    public enum SQarFlags : uint
    {
        Use4kBlockSize = 0x800,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SQarHeader
    {
        public uint Signature;
        public SQarFlags Flags;
        public uint FileCount;
        public uint ContentEntryCount;
        public uint ArchiveSizeInBlocks;
        public uint DataOffset;
        public uint Version;
        public uint Unknown2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FHash
    {
        public ulong Info;

        public static int Compare(FHash a, FHash b) => a.Info < b.Info ? -1 : a.Info == b.Info ? 0 : 1;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CHash
    {
        public ulong Hash;
        public uint BlockOffset;
        public uint Size;

        public static int Compare(CHash a, CHash b) => a.Hash < b.Hash ? -1 : a.Hash == b.Hash ? 0 : 1;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct Md5
    {
        public fixed byte hash[16];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ContentHeader
    {
        public ulong Hash;
        public uint CompressedSize;
        public uint UncompressedSize;
        public Md5 ContentHash;
    }

    private class SQarInfo
    {
        public uint Flags;
        public int BlockSizeExp;
        public uint FileCount;
        public uint ContentListCount;
            
        public FHash[] FileList;
        public CHash[] ContentEntryList;
    }

    private SQarInfo? Info = null;

    public SecureQarFile(Stream stream) : base(stream)
    {
    }

    public bool LoadInfo()
    {
        SQarHeader header = new SQarHeader();
        Stream.ReadExactly(MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref header, 1)));
        if (header.Signature != Signature)
            return false;
        EC1.SEHeader((byte*)&header, (uint)sizeof(SQarHeader), (uint)sizeof(SQarHeader));

        Info = new SQarInfo();
        
        Console.WriteLine($"Created pack with {header.FileCount} files.");

        if (header.FileCount == 0)
            return true;
            
        Info.BlockSizeExp = (header.Flags & SQarFlags.Use4kBlockSize) > 0 ? 12 : 10;
        long archiveSize = Stream.Length;
        if ((archiveSize % (1 << Info.BlockSizeExp)) != 0 || (archiveSize >> Info.BlockSizeExp) != header.ArchiveSizeInBlocks)
            return false;
            
        Info.FileList = new FHash[header.FileCount];
        Stream.ReadExactly(MemoryMarshal.AsBytes(Info.FileList.AsSpan()));
        fixed (FHash* fileListPtr = Info.FileList)
            EC1.SEHeader((byte*)fileListPtr, (uint)(header.FileCount * sizeof(FHash)), (uint)sizeof(FHash));
        
        Info.FileList.Sort(FHash.Compare);

        if (header.ContentEntryCount > 0)
        {
            Info.ContentEntryList = new CHash[header.ContentEntryCount];
            Stream.ReadExactly(MemoryMarshal.AsBytes(Info.ContentEntryList.AsSpan()));
            fixed (CHash* contentHashListPtr = Info.ContentEntryList)
                EC1.SEHeader((byte*)contentHashListPtr, (uint)(header.ContentEntryCount * sizeof(CHash)), (uint)sizeof(CHash));
            
            Info.ContentEntryList.Sort(CHash.Compare);
            
            foreach (CHash hash in Info.ContentEntryList)
                Console.WriteLine($"CHash: 0x{hash.Hash:x8}");
        }

        return true;
    }

    public override MountPointIoHandle? Search(ulong searchHash)
    {
        if (Info == null || Info.FileList.Length == 0)
            return null;

        if (Info.ContentEntryList != null)
        {
            return null;
        }

        FHash[] fileList = Info.FileList;
        uint first = 0;
        uint length = (uint)fileList.LongLength;
        ulong searchKey = ((searchHash & 0xff) << 32) | (searchHash >> 32);
        while (length > 0)
        {
            uint half = length / 2;
            if ((fileList[first + half].Info & 0xFFFFFFFFFF) < searchKey)
            {
                first  += half + 1;
                length -= half + 1;
            }
            else
            {
                length = half;
            }
        }

        if (first < fileList.LongLength && (uint)(searchHash >> 32) == (uint)fileList[first].Info && (byte)searchHash == (byte)(fileList[first].Info >> 32))
        {
            ulong offset = (fileList[first].Info >> 40) << Info.BlockSizeExp;
            Stream.Seek((long)offset, SeekOrigin.Begin);
            
            ContentHeader contentHeader = new ContentHeader();
            Stream.ReadExactly(MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref contentHeader, 1)));
            EC1.SEHeader((byte*)&contentHeader, (uint)sizeof(ContentHeader), (uint)sizeof(ContentHeader));

            return new SQarFileStreamHandle(Stream, contentHeader, offset + (uint)sizeof(ContentHeader), contentHeader.CompressedSize);
        }

        return null;
    }

    public override void PopulateUniqueFileList(uint mountId, Dictionary<ulong, FileInfo> fileList)
    {
        for (uint i = 0; i < Info.FileList.LongLength; i++)
        {
            FHash hash = Info.FileList[i];
            
            ulong offset = (hash.Info >> 40) << Info.BlockSizeExp;
            Stream.Seek((long)offset, SeekOrigin.Begin);
                
            ContentHeader contentHeader = new ContentHeader();
            Stream.ReadExactly(MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref contentHeader, 1)));
            EC1.SEHeader((byte*)&contentHeader, (uint)sizeof(ContentHeader), (uint)sizeof(ContentHeader));

            fileList[contentHeader.Hash] = new FileInfo { MountId = mountId, Hash = hash };
        }
    }

    public override void Export(List<FileInfo> list)
    {
        for (uint i = 0; i < list.Count; i++)
        {
            FHash hash = list[(int)i].Hash;
            
            uint offset = (uint)(hash.Info >> 40) << Info.BlockSizeExp;
            Stream.Seek((long)offset, SeekOrigin.Begin);
                
            ContentHeader contentHeader = new ContentHeader();
            Stream.ReadExactly(MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref contentHeader, 1)));
            EC1.SEHeader((byte*)&contentHeader, (uint)sizeof(ContentHeader), (uint)sizeof(ContentHeader));
        
            byte[] content = new byte[contentHeader.UncompressedSize];
            long contentStreamPos = Stream.Position;
            Stream.ReadExactly(content, 0, (int)contentHeader.CompressedSize);
            fixed (byte* contentPtr = content)
                EC1.SEContent(contentPtr, contentHeader.CompressedSize, (ulong)Math.Max(contentStreamPos - (offset + (uint)sizeof(ContentHeader)), 0), (uint)contentHeader.Hash, true);
                
            // This logic is implicit in the EXE and present in the engine cooking settings.
            // deflate pattern:.*\.fpk$ added.
            // deflate pattern:.*\.fpkd$ added.
            ulong outDecryptedSize = 0;
            if (contentHeader.Hash >> 0x33 is 2629 or 7594)
            {
                using MemoryStream compressedStream = new MemoryStream(content[..(int)contentHeader.CompressedSize]);
                using MemoryStream decompressedStream = new MemoryStream(content);
                using ZLibStream deflateStream = new ZLibStream(compressedStream, CompressionMode.Decompress);
                    
                deflateStream.CopyTo(decompressedStream);
                outDecryptedSize = (ulong)decompressedStream.Length;
            }
            else if (contentHeader.Hash >> 0x33 == 796)
            {
                fixed (byte* contentPtr = content)
                    Decrypter.Decrypt(contentPtr, contentHeader.CompressedSize, contentPtr, &outDecryptedSize);
            }
              
            Console.WriteLine($"Hash: {contentHeader.Hash:x8} | US: {contentHeader.UncompressedSize:D8} | CS: {contentHeader.CompressedSize:D8} | Sig: {System.Text.Encoding.Latin1.GetString(content[..4])}");
            _ = File.WriteAllBytesAsync($"0x{contentHeader.Hash:x8}.dat", content[..(int)outDecryptedSize]);
        }
    }
}

public class SQarFileStreamHandle : MountPointIoHandle
{
     private SecureQarFile.ContentHeader ContentHeader;

     public SQarFileStreamHandle(Stream stream, SecureQarFile.ContentHeader contentHeader, ulong position, ulong size)
     {
         Stream = stream;
         ContentHeader = contentHeader;
         Position = position;
         Size = size;
     }
     
     public override unsafe bool Read(byte[] outData)
     {
         ulong contentStreamPos = (ulong)Stream.Position;
         Stream.ReadExactly(outData, 0, (int)ContentHeader.CompressedSize);
         fixed (byte* contentPtr = outData)
             EC1.SEContent(contentPtr, ContentHeader.CompressedSize, Math.Max(contentStreamPos - Position, 0), (uint)ContentHeader.Hash, true);

         return true;
     }
}