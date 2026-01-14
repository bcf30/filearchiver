using System.Security.Cryptography;
using SharpCompress.Archives;
using SharpCompress.Archives.SevenZip;
using SharpCompress.Common;
using SharpCompress.Writers;

namespace ConsoleApp1;

public class CompressionService
{
    public void CompressFile(string source, string output, string format, string originalFileName)
    {
        switch (format.ToLower())
        {
            case "zip":
                var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                try
                {
                    Directory.CreateDirectory(tempDir);
                    var targetFile = Path.Combine(tempDir, originalFileName);
                    File.Copy(source, targetFile);
                    System.IO.Compression.ZipFile.CreateFromDirectory(tempDir, output);
                }
                finally
                {
                    if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
                }
                break;
            case "7z":
                using (var stream = File.Create(output))
                using (var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.GZip))
                    writer.Write(originalFileName, source);
                break;
            case "tar":
                using (var stream = File.Create(output))
                using (var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.None))
                    writer.Write(originalFileName, source);
                break;
            case "zst":
            case "zstd":
                var tempTarPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tar");
                try
                {
                    using (var tarStream = File.Create(tempTarPath))
                    using (var tarWriter = new System.Formats.Tar.TarWriter(tarStream))
                    {
                        var tarEntry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, originalFileName);
                        using (var fileStream = File.OpenRead(source))
                        {
                            tarEntry.DataStream = fileStream;
                            tarWriter.WriteEntry(tarEntry);
                        }
                    }
                    var tarBytes = File.ReadAllBytes(tempTarPath);
                    File.WriteAllBytes(output, ZstdSharp.Zstd.Compress(tarBytes));
                }
                finally
                {
                    if (File.Exists(tempTarPath)) File.Delete(tempTarPath);
                }
                break;
            case "br":
            case "brotli":
                var tempTarPathBr = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tar");
                try
                {
                    using (var tarStream = File.Create(tempTarPathBr))
                    using (var tarWriter = new System.Formats.Tar.TarWriter(tarStream))
                    {
                        var tarEntry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, originalFileName);
                        using (var fileStream = File.OpenRead(source))
                        {
                            tarEntry.DataStream = fileStream;
                            tarWriter.WriteEntry(tarEntry);
                        }
                    }
                    var tarBytes = File.ReadAllBytes(tempTarPathBr);
                    File.WriteAllBytes(output, BrotliSharpLib.Brotli.CompressBuffer(tarBytes, 0, tarBytes.Length));
                }
                finally
                {
                    if (File.Exists(tempTarPathBr)) File.Delete(tempTarPathBr);
                }
                break;
            default:
                throw new NotSupportedException($"format {format} not supported");
        }
    }

    public void CompressDirectory(string sourceDir, string output, string format)
    {
        switch (format.ToLower())
        {
            case "zip":
                System.IO.Compression.ZipFile.CreateFromDirectory(sourceDir, output);
                break;
            case "7z":
                using (var stream = File.Create(output))
                using (var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.GZip))
                {
                    foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
                    {
                        var entryName = Path.GetRelativePath(sourceDir, file);
                        writer.Write(entryName, file);
                    }
                }
                break;
            case "tar":
                using (var stream = File.Create(output))
                using (var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.None))
                {
                    foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
                    {
                        var entryName = Path.GetRelativePath(sourceDir, file);
                        writer.Write(entryName, file);
                    }
                }
                break;
            case "zst":
            case "zstd":
                var tarPathZst = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tar");
                try
                {
                    using (var tarStream = File.Create(tarPathZst))
                    using (var tarWriter = new System.Formats.Tar.TarWriter(tarStream))
                    {
                        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
                        {
                            var entryName = Path.GetRelativePath(sourceDir, file);
                            var tarEntry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, entryName);
                            using (var fileStream = File.OpenRead(file))
                            {
                                tarEntry.DataStream = fileStream;
                                tarWriter.WriteEntry(tarEntry);
                            }
                        }
                    }
                    var tarBytes = File.ReadAllBytes(tarPathZst);
                    File.WriteAllBytes(output, ZstdSharp.Zstd.Compress(tarBytes));
                }
                finally
                {
                    if (File.Exists(tarPathZst)) File.Delete(tarPathZst);
                }
                break;
            case "br":
            case "brotli":
                var tarPathBr = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tar");
                try
                {
                    using (var tarStream = File.Create(tarPathBr))
                    using (var tarWriter = new System.Formats.Tar.TarWriter(tarStream))
                    {
                        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
                        {
                            var entryName = Path.GetRelativePath(sourceDir, file);
                            var tarEntry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, entryName);
                            using (var fileStream = File.OpenRead(file))
                            {
                                tarEntry.DataStream = fileStream;
                                tarWriter.WriteEntry(tarEntry);
                            }
                        }
                    }
                    var tarBytes = File.ReadAllBytes(tarPathBr);
                    File.WriteAllBytes(output, BrotliSharpLib.Brotli.CompressBuffer(tarBytes, 0, tarBytes.Length));
                }
                finally
                {
                    if (File.Exists(tarPathBr)) File.Delete(tarPathBr);
                }
                break;
            default:
                throw new NotSupportedException($"format {format} not supported");
        }
    }

    public void ExtractFile(string archive, string destination)
    {
        var fileName = Path.GetFileName(archive).ToLower();
        Console.WriteLine($"DEBUG: Extracting file: {fileName}");
        
        if (fileName.EndsWith(".tar.zst") || fileName.EndsWith(".tar.zstd"))
        {
            Console.WriteLine("DEBUG: Using ZSTD decompression for .tar.zst");
            var compressed = File.ReadAllBytes(archive);
            byte[] decompressed;
            try { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 10); }
            catch { try { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 50); }
                    catch { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 100); } }
            
            Console.WriteLine($"DEBUG: Decompressed {decompressed.Length} bytes");
            ExtractTarFromBytes(decompressed, destination, archive);
            return;
        }
        
        if (fileName.EndsWith(".tar.br") || fileName.EndsWith(".tar.brotli"))
        {
            Console.WriteLine("DEBUG: Using Brotli decompression for .tar.br");
            var compressed = File.ReadAllBytes(archive);
            var decompressed = BrotliSharpLib.Brotli.DecompressBuffer(compressed, 0, compressed.Length);
            
            Console.WriteLine($"DEBUG: Decompressed {decompressed.Length} bytes");
            ExtractTarFromBytes(decompressed, destination, archive);
            return;
        }

        // Handle legacy .zst and .br files (for backward compatibility)
        var ext = Path.GetExtension(archive).ToLower();
        if (ext == ".zst" || ext == ".zstd")
        {
            Console.WriteLine("DEBUG: Using ZSTD decompression for legacy .zst");
            var compressed = File.ReadAllBytes(archive);
            byte[] decompressed;
            try { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 10); }
            catch { try { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 50); }
                    catch { decompressed = ZstdSharp.Zstd.Decompress(compressed, compressed.Length * 100); } }
            
            ExtractTarFromBytes(decompressed, destination, archive);
            return;
        }
        
        if (ext == ".br" || ext == ".brotli")
        {
            Console.WriteLine("DEBUG: Using Brotli decompression for legacy .br");
            var compressed = File.ReadAllBytes(archive);
            var decompressed = BrotliSharpLib.Brotli.DecompressBuffer(compressed, 0, compressed.Length);
            
            ExtractTarFromBytes(decompressed, destination, archive);
            return;
        }
        
        // Handle other formats
        if (ext == ".zip")
        {
            System.IO.Compression.ZipFile.ExtractToDirectory(archive, destination);
        }
        else if (ext == ".7z")
        {
            using var arch = SevenZipArchive.Open(archive);
            foreach (var entry in arch.Entries.Where(e => !e.IsDirectory))
                entry.WriteToDirectory(destination, new ExtractionOptions { ExtractFullPath = true, Overwrite = true });
        }
        else if (ext == ".tar")
        {
            Console.WriteLine("DEBUG: Using TAR extraction");
            try
            {
                using var arch = ArchiveFactory.Open(archive);
                foreach (var entry in arch.Entries.Where(e => !e.IsDirectory))
                    entry.WriteToDirectory(destination, new ExtractionOptions { ExtractFullPath = true, Overwrite = true });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DEBUG: TAR extraction failed: {ex.Message}");
                throw new NotSupportedException($"TAR extraction failed: {ex.Message}. Archive may be corrupted or use unsupported compression.");
            }
        }
        else
        {
            throw new NotSupportedException($"Archive format {ext} not supported. Supported formats: Zip, 7Zip, Tar, Zstd (.tar.zst), Brotli (.tar.br)");
        }
    }

    private void ExtractTarFromBytes(byte[] tarBytes, string destination, string originalArchive)
    {
        var tempTarPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tar");
        try
        {
            File.WriteAllBytes(tempTarPath, tarBytes);
            
            using (var tarStream = File.OpenRead(tempTarPath))
            using (var tarReader = new System.Formats.Tar.TarReader(tarStream))
            {
                System.Formats.Tar.TarEntry? entry;
                while ((entry = tarReader.GetNextEntry()) != null)
                {
                    if (entry.EntryType == System.Formats.Tar.TarEntryType.RegularFile)
                    {
                        var destinationPath = Path.Combine(destination, entry.Name);
                        var destinationDir = Path.GetDirectoryName(destinationPath);
                        if (!string.IsNullOrEmpty(destinationDir) && !Directory.Exists(destinationDir))
                        {
                            Directory.CreateDirectory(destinationDir);
                        }
                        
                        using (var fileStream = File.Create(destinationPath))
                        {
                            entry.DataStream?.CopyTo(fileStream);
                        }
                        Console.WriteLine($"DEBUG: Extracted: {entry.Name}");
                    }
                }
            }
            Console.WriteLine("DEBUG: Successfully extracted all TAR contents");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DEBUG: TAR extraction failed: {ex.Message}");
            var baseName = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(originalArchive));
            var singleFileName = baseName.Length > 0 ? baseName : "extracted_file";
            var singleFilePath = Path.Combine(destination, singleFileName);
            File.WriteAllBytes(singleFilePath, tarBytes);
        }
        finally
        {
            if (File.Exists(tempTarPath))
            {
                try { File.Delete(tempTarPath); }
                catch { Console.WriteLine("DEBUG: Failed to delete temp TAR file"); }
            }
        }
    }

    public string CalculateHash(string filePath, string algorithm)
    {
        using var stream = File.OpenRead(filePath);
        byte[] hash;

        switch (algorithm.ToLower())
        {
            case "md5": hash = MD5.HashData(stream); break;
            case "sha1": hash = SHA1.HashData(stream); break;
            case "sha256": hash = SHA256.HashData(stream); break;
            case "sha512": hash = SHA512.HashData(stream); break;
            case "crc32": return CalculateCRC32(filePath).ToString("X8");
            default: throw new NotSupportedException($"algorithm {algorithm} not supported");
        }

        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public bool VerifyHash(string filePath, string expectedHash, string algorithm)
    {
        var actualHash = CalculateHash(filePath, algorithm);
        return string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase);
    }

    private static uint CalculateCRC32(string filePath)
    {
        const uint polynomial = 0xEDB88320;
        var table = new uint[256];
        
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
                crc = (crc & 1) == 1 ? (crc >> 1) ^ polynomial : crc >> 1;
            table[i] = crc;
        }
        
        uint result = 0xFFFFFFFF;
        using var stream = File.OpenRead(filePath);
        var buffer = new byte[8192];
        int bytesRead;
        
        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            for (int i = 0; i < bytesRead; i++)
                result = table[(result ^ buffer[i]) & 0xFF] ^ (result >> 8);
        
        return result ^ 0xFFFFFFFF;
    }
}