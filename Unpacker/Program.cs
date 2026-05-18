using System.Xml;
using Fox.FileSystem;

namespace FoxKit.ModManager.Unpacker
{
    static unsafe class Program
    {
        static void Main(string[] args)
        {
            // Setup
            if (args.Length < 1)
                return;

            string exePath = args[0];
            string exeName = Path.GetFileName(exePath);
            if (exeName != "mgsvtpp.exe" && exeName != "Tpp_main_win64.exe")
                return;

            FileSystemLocator.ResetMediaRootName(null, Path.GetDirectoryName(exePath), null);
            
            // Manifest
            ReadOnlySpan<byte> manifestData;
            using (MountPoint manifestMount = MountPoint.CreateMountPoint("fmanifest", FileSystemLocator.GetChunkFileName("chunk0.dat")))
            {
                if (manifestMount.Search(0xac8445ada1c810e4) is not MountPointIoHandle manifestHandle)
                    return;

                byte[] manifestDataBuffer = new byte[manifestHandle.GetSize()];
                if (!manifestHandle.Read(manifestDataBuffer))
                    return;
            
                ulong decryptedManifestSize = 0;
                fixed (byte* manifestDataPtr = manifestDataBuffer)
                    decryptedManifestSize = Decrypter.Decrypt(manifestDataPtr, manifestHandle.GetSize(), manifestDataPtr, &decryptedManifestSize);

                manifestData = manifestDataBuffer.AsSpan(0, (int)decryptedManifestSize);
            }
            
            string manifestString = System.Text.Encoding.Latin1.GetString(manifestData);
            XmlReader xmlReader = XmlReader.Create(new StringReader(manifestString));

            if (!xmlReader.ReadToFollowing("chunks"))
                return;

            List<MountPoint> mountPoints = new List<MountPoint>();
            if (xmlReader.ReadToDescendant("chunk"))
            {
                do
                {
                    if (xmlReader.GetAttribute("label") is not string name)
                        continue;
                    
                    if (xmlReader.GetAttribute("qar") is not string path)
                        continue;
                    
                    MountPoint mountPoint = MountPoint.CreateMountPoint(name, FileSystemLocator.GetChunkFileName(path));
                    mountPoints.Add(mountPoint);

                    if (xmlReader.GetAttribute("textures") is string texturesPath)
                    {
                        MountPoint textureMountPoint = MountPoint.CreateMountPoint(texturesPath, FileSystemLocator.GetChunkFileName(texturesPath));
                        mountPoints.Add(textureMountPoint);
                    }
                } while (xmlReader.ReadToNextSibling("chunk"));
            }
            
            Dictionary<ulong, Fox.FileSystem.FileInfo> fileList = new Dictionary<ulong, Fox.FileSystem.FileInfo>();
            for (uint i = (uint)mountPoints.Count - 1; i < mountPoints.Count; i--)
                mountPoints[(int)i].PopulateUniqueFileList(i, fileList);

            List<Fox.FileSystem.FileInfo>[] exportInfos = new List<Fox.FileSystem.FileInfo>[mountPoints.Count];
            for (uint i = 0; i < mountPoints.Count; i++)
                exportInfos[i] = new List<Fox.FileSystem.FileInfo>();
            
            foreach ((_, Fox.FileSystem.FileInfo info) in fileList)
                exportInfos[info.MountId].Add(info);

            Parallel.For(0, exportInfos.Length, i =>
            {
                MountPoint mountPoint = mountPoints[i];
                List<Fox.FileSystem.FileInfo> mountExportInfo = exportInfos[i];
                
                mountPoint.Export(mountExportInfo);
                
                //Console.WriteLine($"Hash: {contentHeader.Hash:x8} | US: {contentHeader.UncompressedSize:D8} | CS: {contentHeader.CompressedSize:D8} | Sig: {System.Text.Encoding.Latin1.GetString(content[..4])}");
            });

            return;
        }
    }
}