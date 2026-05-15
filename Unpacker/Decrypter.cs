using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Fox.FileSystem;

public unsafe class Decrypter
{
    // Magic numbers identifying the two supported formats
    private const uint EncryptedContentSignature = 0xA0F8EFE6;
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct EncryptedContentHeader
    {
        public uint Signature;
        public uint Seed;
    }
    
    private const uint MagicEncryptedCompressed = 0xE3F8EFE6;
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct CompressedContentHeader
    {
        public uint UncompressedSize;
        public uint CompressedSize;
    }

    public static ulong Decrypt(byte* data, ulong dataSize, byte* outData, ulong* outDecryptedSize)
    {
        if (dataSize <= (uint)sizeof(EncryptedContentHeader))
            return dataSize;

        EncryptedContentHeader encryptionHeader = *(EncryptedContentHeader*)data;

        if (encryptionHeader.Signature == EncryptedContentSignature)
        {
            dataSize -= (uint)sizeof(EncryptedContentHeader);
            data += (uint)sizeof(EncryptedContentHeader);

            *outDecryptedSize = dataSize;
            
            if (outData != null)
                Decrypt(outData, data, dataSize, encryptionHeader.Seed);
            
            return dataSize;
        }
        else if (encryptionHeader.Signature == MagicEncryptedCompressed)
        {
            dataSize -= (uint)sizeof(EncryptedContentHeader);
            data += (uint)sizeof(EncryptedContentHeader);
            
            if (dataSize <= (uint)sizeof(CompressedContentHeader))
                return dataSize;
            
            CompressedContentHeader compressionHeader = *(CompressedContentHeader*)data;
            data += sizeof(CompressedContentHeader);
            dataSize -= (uint)sizeof(CompressedContentHeader);

            uint uncompressedSize = compressionHeader.UncompressedSize;
            uint compressedSize   = compressionHeader.CompressedSize;

            if (compressedSize != uncompressedSize)
            {
                if (outData != null)
                {
                    Decrypt(outData, data, compressedSize, encryptionHeader.Seed);

                    using UnmanagedMemoryStream compressedStream = new UnmanagedMemoryStream(data, compressedSize);
                    using UnmanagedMemoryStream decompressedStream = new UnmanagedMemoryStream(outData, uncompressedSize);
                    using ZLibStream deflateStream = new ZLibStream(compressedStream, CompressionMode.Decompress);
                    deflateStream.CopyTo(decompressedStream);
                    ulong decompressedSize = (ulong)decompressedStream.Length;

                    return decompressedSize;
                }

                *outDecryptedSize = compressedSize;
                return compressedSize;
            }

            *outDecryptedSize = compressedSize;

            if (outData != null)
                Decrypt(outData, data, compressedSize, encryptionHeader.Seed);

            return compressedSize;
        }

        return dataSize;
    }

    private static void Decrypt(byte* destination, byte* source, ulong size, uint seed)
    {
        uint blockCount = (uint)size / sizeof(uint);
        uint blockDataSize = blockCount * sizeof(uint);
        
        uint* sourceBlocks = (uint*)source;
        uint* destBlocks = (uint*)destination;

        uint key = ((seed ^ 0x6576) << 16) | seed;
        uint addend = seed * 0x116;

        for (uint i = 0; i < blockCount; i++)
        {
            destBlocks[i] = sourceBlocks[i] ^ key;
            key = key * 0x2E90EDD + addend;
        }

        ulong remainder = size - blockDataSize;
        if (remainder != 0)
            Buffer.MemoryCopy(source + blockDataSize, destination + blockDataSize, remainder, remainder);
    }
}