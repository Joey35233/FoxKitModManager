using System.Runtime.InteropServices;

namespace Fox.FileSystem;

public static class FileSystemLocator
{
    public static string MediaRootPath;
    public static string DataStrapRoot = "master";
    public static string PatchDataName;

    public static void ResetMediaRootName(string dataStrapRoot, string mediaRootPath, string patchDataName)
    {
        if (dataStrapRoot != null)
            DataStrapRoot = dataStrapRoot;

        if (mediaRootPath != null)
        {
            MediaRootPath = mediaRootPath;
            if (!Path.EndsInDirectorySeparator(MediaRootPath))
                MediaRootPath += Path.DirectorySeparatorChar;
        }

        PatchDataName = patchDataName;
    }

    public static string GetChunkFileName(string chunkName)
    {
        string basePath = $"{MediaRootPath}{DataStrapRoot}\\";
        
        if (chunkName != null)
            return basePath + chunkName;
        else
            return basePath;
    }
}

public abstract class MountPoint : IDisposable
{
    private static Dictionary<string, MountPoint> MountPoints = new Dictionary<string, MountPoint>();

    protected string Name;
    protected Stream Stream;

    protected MountPoint(Stream stream)
    {
        Stream = stream;
    }

    public static MountPoint CreateMountPoint(string name, string path)
    {
        SecureQarFile mountPoint = new SecureQarFile(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
        
        mountPoint.Name = name;
        if (mountPoint.LoadInfo())
        {
            MountPoints[mountPoint.Name] = mountPoint;

            return mountPoint;
        }

        return null;
    }

    public abstract MountPointIoHandle? Search(ulong searchHash);

    public abstract void PopulateUniqueFileList(uint mountId, Dictionary<ulong, FileInfo> fileList);

    public abstract void Export(List<FileInfo> list);
    
    public void Dispose()
    {
        MountPoints.Remove(this.Name);
        Stream.Dispose();
    }
}

public abstract class MountPointIoHandle
{
    protected Stream Stream;

    protected ulong Position;
    protected ulong Size;

    public ulong GetSize() => Size;
    public abstract bool Read(byte[] outData);
}

public struct FileInfo
{
    public uint MountId;
    public SecureQarFile.FHash Hash;
}