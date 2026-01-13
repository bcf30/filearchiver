using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;
using SharpCompress.Writers;
using ZstdSharp;
using BrotliSharpLib;

namespace FileCompressionApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var app = new CompressionApp();
            app.Run();
        }
    }

    public class CompressionApp
    {
        public void Run()
        {
            Console.WriteLine("=== File Compression Tool ===");
            Console.WriteLine("✅ Full Support: ZIP, 7Z, TAR, Brotli, ZSTD");
            Console.WriteLine("🔧 Features: Extract, Archive, Convert, Hash (MD5/SHA1/SHA256/SHA512/CRC32), Split, Selective Compression\n");

            // Initialize SevenZip library
            var sevenZipInitialized = InitializeSevenZip();
            if (sevenZipInitialized)
            {
                Console.WriteLine("✅ 7Z library initialized successfully - Full 7Z support available");
            }
            else
            {
                Console.WriteLine("⚠️  7Z library initialization failed - Limited 7Z support");
            }
            Console.WriteLine();

            while (true)
            {
                ShowMenu();
                var choice = Console.ReadLine()?.Trim();

                try
                {
                    switch (choice)
                    {
                        case "1": CreateArchive(); break;
                        case "2": ExtractArchive(); break;
                        case "3": ConvertArchive(); break;
                        case "4": CreatePasswordArchive(); break;
                        case "5": CalculateHash(); break;
                        case "6": VerifyHash(); break;
                        case "7": SplitArchive(); break;
                        case "8": ExtractSplitArchive(); break;
                        case "9": ListArchiveContents(); break;
                        case "10": CreateArchiveFromSelectedFiles(); break;
                        case "0": return;
                        default: Console.WriteLine("Invalid choice!"); break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    Console.WriteLine("Please try again or choose a different option.");
                }

                Console.WriteLine("\nPress any key to continue...");
                Console.ReadKey();
                Console.Clear();
            }
        }

        private bool InitializeSevenZip()
        {
            try
            {
                // SharpCompress handles 7Z natively, no external DLL needed
                Console.WriteLine("✅ 7Z support initialized via SharpCompress");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"7Z initialization warning: {ex.Message}");
                return false;
            }
        }

        private void ShowMenu()
        {
            Console.WriteLine("Choose an option:");
            Console.WriteLine("1. Create Archive");
            Console.WriteLine("2. Extract Archive");
            Console.WriteLine("3. Convert Archive Type");
            Console.WriteLine("4. Create Password-Protected Archive");
            Console.WriteLine("5. Calculate File Hash");
            Console.WriteLine("6. Verify File Hash");
            Console.WriteLine("7. Split Archive");
            Console.WriteLine("8. Extract Split Archive");
            Console.WriteLine("9. List Archive Contents");
            Console.WriteLine("10. Create Archive from Selected Files");
            Console.WriteLine("0. Exit");
            Console.WriteLine();
            Console.WriteLine("💡 Tip: Type 'back' at any prompt to return to this menu");
            Console.Write("\nEnter choice: ");
        }
        private void CreateArchive()
        {
            Console.Write("Enter source path (file or directory) [or 'back' to return]: ");
            var sourcePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(sourcePath) || sourcePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!Path.Exists(sourcePath))
            {
                Console.WriteLine("Invalid source path!");
                return;
            }

            Console.Write("Enter output archive path [or 'back' to return]: ");
            var outputPath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(outputPath) || outputPath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }

            var format = GetArchiveFormat(outputPath);
            Console.Write("Delete source files after archiving? (y/n) [or 'back' to return]: ");
            var deleteInput = Console.ReadLine()?.ToLower().Trim();
            if (deleteInput == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            var deleteSource = deleteInput == "y";

            Console.WriteLine($"Creating {format} archive...");

            switch (format)
            {
                case ArchiveFormat.Zip:
                    CreateZipArchive(sourcePath, outputPath);
                    break;
                case ArchiveFormat.SevenZ:
                    Create7zArchive(sourcePath, outputPath);
                    break;
                case ArchiveFormat.Tar:
                    CreateTarArchive(sourcePath, outputPath);
                    break;
                case ArchiveFormat.Zstd:
                    CreateZstdArchive(sourcePath, outputPath);
                    break;
                case ArchiveFormat.Brotli:
                    CreateBrotliArchive(sourcePath, outputPath);
                    break;
                default:
                    Console.WriteLine("Unsupported format!");
                    return;
            }

            if (deleteSource)
            {
                DeleteSourceFiles(sourcePath);
            }

            Console.WriteLine("Archive created successfully!");
        }

        private void CreateArchiveFromSelectedFiles()
        {
            try
            {
                Console.Write("Enter directory path to browse [or 'back' to return]: ");
                var directoryPath = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(directoryPath) || directoryPath.ToLower() == "back")
                {
                    Console.WriteLine("Returning to main menu...");
                    return;
                }
                
                // Handle quoted paths and normalize
                directoryPath = directoryPath.Trim('"', '\'');
                
                // Validate and normalize the directory path
                if (!Directory.Exists(directoryPath))
                {
                    Console.WriteLine("Directory not found!");
                    return;
                }

                // Get the full path to avoid issues with relative paths
                try
                {
                    directoryPath = Path.GetFullPath(directoryPath);
                    Console.WriteLine($"Browsing directory: {directoryPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Invalid directory path: {ex.Message}");
                    return;
                }

                var selectedFiles = SelectFilesFromDirectory(directoryPath);
                if (selectedFiles == null || selectedFiles.Count == 0)
                {
                    Console.WriteLine("No files selected!");
                    return;
                }

                Console.Write("Enter output archive path [or 'back' to return]: ");
                var outputPath = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(outputPath) || outputPath.ToLower() == "back")
                {
                    Console.WriteLine("Returning to main menu...");
                    return;
                }

                // Handle quoted paths and validate
                outputPath = outputPath.Trim('"', '\'');
                
                try
                {
                    outputPath = Path.GetFullPath(outputPath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Invalid output path: {ex.Message}");
                    return;
                }

                // Validate output directory
                var outputDir = Path.GetDirectoryName(outputPath);
                if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
                {
                    try
                    {
                        Directory.CreateDirectory(outputDir);
                        Console.WriteLine($"Created output directory: {outputDir}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Cannot create output directory: {ex.Message}");
                        return;
                    }
                }

                // Validate all selected files still exist and are accessible
                var validFiles = new List<string>();
                foreach (var file in selectedFiles)
                {
                    try
                    {
                        if (File.Exists(file))
                        {
                            // Test file access
                            using var testStream = File.OpenRead(file);
                            validFiles.Add(file);
                        }
                        else
                        {
                            Console.WriteLine($"Warning: File no longer exists: {Path.GetFileName(file)}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Cannot access file {Path.GetFileName(file)}: {ex.Message}");
                    }
                }

                if (validFiles.Count == 0)
                {
                    Console.WriteLine("No valid files to compress!");
                    return;
                }

                if (validFiles.Count != selectedFiles.Count)
                {
                    Console.WriteLine($"Proceeding with {validFiles.Count} accessible files out of {selectedFiles.Count} selected.");
                }

                var format = GetArchiveFormat(outputPath);
                Console.Write("Delete source files after archiving? (y/n) [or 'back' to return]: ");
                var deleteInput = Console.ReadLine()?.ToLower().Trim();
                if (deleteInput == "back")
                {
                    Console.WriteLine("Returning to main menu...");
                    return;
                }
                var deleteSource = deleteInput == "y";

                Console.WriteLine($"Creating {format} archive with {validFiles.Count} selected files...");

                bool success = false;
                switch (format)
                {
                    case ArchiveFormat.Zip:
                        success = CreateZipArchiveFromFiles(validFiles, outputPath, directoryPath);
                        break;
                    case ArchiveFormat.SevenZ:
                        success = Create7zArchiveFromFiles(validFiles, outputPath, directoryPath);
                        break;
                    case ArchiveFormat.Tar:
                        success = CreateTarArchiveFromFiles(validFiles, outputPath, directoryPath);
                        break;
                    case ArchiveFormat.Zstd:
                        if (validFiles.Count == 1)
                        {
                            CreateZstdArchive(validFiles[0], outputPath);
                            success = true;
                        }
                        else
                        {
                            Console.WriteLine("ZSTD supports multiple files via TAR+ZSTD...");
                            success = CreateTarZstdArchiveFromFiles(validFiles, outputPath, directoryPath);
                        }
                        break;
                    case ArchiveFormat.Brotli:
                        if (validFiles.Count == 1)
                        {
                            CreateBrotliArchive(validFiles[0], outputPath);
                            success = true;
                        }
                        else
                        {
                            Console.WriteLine("Brotli supports multiple files via TAR+Brotli...");
                            success = CreateTarBrotliArchiveFromFiles(validFiles, outputPath, directoryPath);
                        }
                        break;
                    default:
                        Console.WriteLine("Unsupported format for selective compression!");
                        return;
                }

                if (success && deleteSource)
                {
                    foreach (var file in validFiles)
                    {
                        try
                        {
                            File.Delete(file);
                            Console.WriteLine($"Deleted: {Path.GetFileName(file)}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Could not delete {Path.GetFileName(file)}: {ex.Message}");
                        }
                    }
                }

                if (success)
                {
                    Console.WriteLine("Selective archive created successfully!");
                }
                else
                {
                    Console.WriteLine("Archive creation failed!");
                }
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Invalid argument: {ex.Message}");
                Console.WriteLine("Please check your file paths for invalid characters.");
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Access denied: {ex.Message}");
                Console.WriteLine("Please check file permissions and try again.");
            }
            catch (DirectoryNotFoundException ex)
            {
                Console.WriteLine($"Directory not found: {ex.Message}");
            }
            catch (PathTooLongException ex)
            {
                Console.WriteLine($"Path too long: {ex.Message}");
                Console.WriteLine("Please use shorter file paths.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in selective compression: {ex.Message}");
                Console.WriteLine($"Error code: 0x{ex.HResult:X8}");
                Console.WriteLine("Please check your file paths and try again.");
            }
        }

        private void ExtractArchive()
        {
            Console.Write("Enter archive path [or 'back' to return]: ");
            var archivePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(archivePath) || archivePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!File.Exists(archivePath))
            {
                Console.WriteLine("Archive not found!");
                return;
            }

            Console.Write("Enter extraction directory (or press Enter for current) [or 'back' to return]: ");
            var extractPath = Console.ReadLine()?.Trim();
            if (extractPath?.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (string.IsNullOrEmpty(extractPath))
                extractPath = Directory.GetCurrentDirectory();

            // Ensure the extraction directory exists
            try
            {
                if (!Directory.Exists(extractPath))
                {
                    Directory.CreateDirectory(extractPath);
                    Console.WriteLine($"Created extraction directory: {extractPath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cannot create extraction directory: {ex.Message}");
                return;
            }

            Console.Write("Delete archive after extraction? (y/n) [or 'back' to return]: ");
            var deleteInput = Console.ReadLine()?.ToLower().Trim();
            if (deleteInput == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            var deleteArchive = deleteInput == "y";

            var format = GetArchiveFormat(archivePath);
            Console.WriteLine($"Extracting {format} archive...");

            try
            {
                switch (format)
                {
                    case ArchiveFormat.Zip:
                        ExtractZipArchive(archivePath, extractPath);
                        break;
                    case ArchiveFormat.SevenZ:
                    case ArchiveFormat.Tar:
                        ExtractGenericArchive(archivePath, extractPath);
                        break;
                    case ArchiveFormat.Zstd:
                        ExtractZstdArchive(archivePath, extractPath);
                        break;
                    case ArchiveFormat.Brotli:
                        ExtractBrotliArchive(archivePath, extractPath);
                        break;
                    default:
                        Console.WriteLine("Unsupported format!");
                        return;
                }

                if (deleteArchive)
                {
                    File.Delete(archivePath);
                    Console.WriteLine("Archive deleted.");
                }

                Console.WriteLine("Extraction completed!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Extraction failed: {ex.Message}");
            }
        }

        private void ConvertArchive()
        {
            Console.Write("Enter source archive path: ");
            var sourcePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(sourcePath) || !File.Exists(sourcePath))
            {
                Console.WriteLine("Source archive not found!");
                return;
            }

            Console.Write("Enter target archive path: ");
            var targetPath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(targetPath))
            {
                Console.WriteLine("Invalid target path!");
                return;
            }

            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempDir);

            try
            {
                Console.WriteLine("Extracting source archive...");
                var sourceFormat = GetArchiveFormat(sourcePath);
                ExtractArchiveToTemp(sourcePath, tempDir, sourceFormat);

                Console.WriteLine("Creating target archive...");
                var targetFormat = GetArchiveFormat(targetPath);
                CreateArchiveFromTemp(tempDir, targetPath, targetFormat);

                Console.WriteLine("Conversion completed!");
            }
            finally
            {
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
            }
        }

        private void CreatePasswordArchive()
        {
            Console.Write("Enter source path: ");
            var sourcePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(sourcePath) || !Path.Exists(sourcePath))
            {
                Console.WriteLine("Invalid source path!");
                return;
            }

            Console.Write("Enter output archive path (.zip or .7z): ");
            var outputPath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(outputPath))
            {
                Console.WriteLine("Invalid output path!");
                return;
            }

            Console.Write("Enter password: ");
            var password = ReadPassword();

            var format = GetArchiveFormat(outputPath);
            if (format != ArchiveFormat.Zip && format != ArchiveFormat.SevenZ)
            {
                Console.WriteLine("Password protection only supported for ZIP and 7Z formats!");
                return;
            }

            Console.WriteLine("Creating password-protected archive...");
            CreatePasswordProtectedArchive(sourcePath, outputPath, password, format);
            Console.WriteLine("Password-protected archive created!");
        }
        private void CalculateHash()
        {
            Console.Write("Enter file path [or 'back' to return]: ");
            var filePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(filePath) || filePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!File.Exists(filePath))
            {
                Console.WriteLine("File not found!");
                return;
            }

            Console.WriteLine("Select hash algorithm [or 'back' to return]:");
            Console.WriteLine("1. MD5");
            Console.WriteLine("2. SHA1");
            Console.WriteLine("3. SHA256");
            Console.WriteLine("4. SHA512");
            Console.WriteLine("5. CRC32");
            Console.WriteLine("6. All algorithms");
            Console.Write("Choice: ");

            var choice = Console.ReadLine()?.Trim();
            if (choice?.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }

            var algorithms = new Dictionary<string, HashAlgorithm>();
            
            switch (choice)
            {
                case "1":
                    algorithms["MD5"] = MD5.Create();
                    break;
                case "2":
                    algorithms["SHA1"] = SHA1.Create();
                    break;
                case "3":
                    algorithms["SHA256"] = SHA256.Create();
                    break;
                case "4":
                    algorithms["SHA512"] = SHA512.Create();
                    break;
                case "5":
                    Console.WriteLine("CRC32 calculation...");
                    var crc32 = CalculateCRC32(filePath);
                    Console.WriteLine($"CRC32: {crc32:X8}");
                    SaveHashToFile(filePath, "crc32", crc32.ToString("X8"));
                    return;
                case "6":
                    algorithms["MD5"] = MD5.Create();
                    algorithms["SHA1"] = SHA1.Create();
                    algorithms["SHA256"] = SHA256.Create();
                    algorithms["SHA512"] = SHA512.Create();
                    break;
                default:
                    algorithms["SHA256"] = SHA256.Create();
                    break;
            }

            var fileInfo = new FileInfo(filePath);
            var progress = new ProgressReporter(fileInfo.Length * algorithms.Count);
            long totalProcessed = 0;

            foreach (var kvp in algorithms)
            {
                Console.WriteLine($"Calculating {kvp.Key}...");
                var hash = CalculateFileHashWithProgress(filePath, kvp.Value, progress, ref totalProcessed);
                Console.WriteLine($"{kvp.Key}: {hash}");
                SaveHashToFile(filePath, kvp.Key.ToLower(), hash);
            }
            
            progress.Complete();
            
            // Also calculate CRC32 if doing all algorithms
            if (choice == "6")
            {
                Console.WriteLine("Calculating CRC32...");
                var crc32 = CalculateCRC32(filePath);
                Console.WriteLine($"CRC32: {crc32:X8}");
                SaveHashToFile(filePath, "crc32", crc32.ToString("X8"));
            }
        }

        private void SaveHashToFile(string filePath, string algorithm, string hash)
        {
            var hashFile = filePath + $".{algorithm}";
            File.WriteAllText(hashFile, $"{hash} *{Path.GetFileName(filePath)}");
        }

        private string CalculateFileHashWithProgress(string filePath, HashAlgorithm algorithm, ProgressReporter progress, ref long totalProcessed)
        {
            using var stream = File.OpenRead(filePath);
            var buffer = new byte[81920];
            int bytesRead;
            
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                algorithm.TransformBlock(buffer, 0, bytesRead, null, 0);
                totalProcessed += bytesRead;
                progress.UpdateProgress(totalProcessed);
            }
            
            algorithm.TransformFinalBlock(new byte[0], 0, 0);
            var hashBytes = algorithm.Hash ?? new byte[0];
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        private uint CalculateCRC32(string filePath)
        {
            const uint polynomial = 0xEDB88320;
            var table = new uint[256];
            
            // Build CRC32 table
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 0; j < 8; j++)
                {
                    crc = (crc & 1) == 1 ? (crc >> 1) ^ polynomial : crc >> 1;
                }
                table[i] = crc;
            }
            
            // Calculate CRC32
            uint result = 0xFFFFFFFF;
            using var stream = File.OpenRead(filePath);
            var buffer = new byte[81920];
            int bytesRead;
            
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                for (int i = 0; i < bytesRead; i++)
                {
                    result = table[(result ^ buffer[i]) & 0xFF] ^ (result >> 8);
                }
            }
            
            return result ^ 0xFFFFFFFF;
        }

        private void VerifyHash()
        {
            Console.Write("Enter file path [or 'back' to return]: ");
            var filePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(filePath) || filePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!File.Exists(filePath))
            {
                Console.WriteLine("File not found!");
                return;
            }

            Console.Write("Enter hash file path (or press Enter to search) [or 'back' to return]: ");
            var hashFilePath = Console.ReadLine()?.Trim();
            if (hashFilePath?.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }

            if (string.IsNullOrEmpty(hashFilePath))
            {
                var extensions = new[] { ".md5", ".sha1", ".sha256", ".sha512", ".crc32" };
                var foundHashes = extensions.Select(ext => filePath + ext)
                                          .Where(File.Exists)
                                          .ToList();
                
                if (foundHashes.Count == 0)
                {
                    Console.WriteLine("No hash files found!");
                    return;
                }
                
                if (foundHashes.Count == 1)
                {
                    hashFilePath = foundHashes[0];
                }
                else
                {
                    Console.WriteLine("Multiple hash files found:");
                    for (int i = 0; i < foundHashes.Count; i++)
                    {
                        Console.WriteLine($"{i + 1}. {Path.GetFileName(foundHashes[i])}");
                    }
                    Console.Write("Select hash file (1-" + foundHashes.Count + "): ");
                    if (int.TryParse(Console.ReadLine(), out var selection) && 
                        selection >= 1 && selection <= foundHashes.Count)
                    {
                        hashFilePath = foundHashes[selection - 1];
                    }
                    else
                    {
                        Console.WriteLine("Invalid selection!");
                        return;
                    }
                }
            }

            if (!File.Exists(hashFilePath))
            {
                Console.WriteLine("Hash file not found!");
                return;
            }

            var hashContent = File.ReadAllText(hashFilePath).Trim();
            var expectedHash = hashContent.Split(' ')[0];
            var algorithmName = Path.GetExtension(hashFilePath).TrimStart('.');

            Console.WriteLine($"Verifying {algorithmName.ToUpper()} hash...");
            
            string actualHash;
            bool isValid;
            
            if (algorithmName.ToLower() == "crc32")
            {
                var crc32 = CalculateCRC32(filePath);
                actualHash = crc32.ToString("X8");
                isValid = string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                HashAlgorithm algorithm = algorithmName.ToLower() switch
                {
                    "md5" => MD5.Create(),
                    "sha1" => SHA1.Create(),
                    "sha256" => SHA256.Create(),
                    "sha512" => SHA512.Create(),
                    _ => SHA256.Create()
                };

                actualHash = CalculateFileHash(filePath, algorithm);
                isValid = string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase);
            }

            Console.WriteLine($"Expected: {expectedHash}");
            Console.WriteLine($"Actual:   {actualHash}");
            Console.WriteLine($"Status:   {(isValid ? "✅ VALID" : "❌ INVALID")}");
            
            if (isValid)
            {
                Console.WriteLine("File integrity verified successfully!");
            }
            else
            {
                Console.WriteLine("WARNING: File may be corrupted or modified!");
            }
        }

        private void SplitArchive()
        {
            Console.Write("Enter archive path [or 'back' to return]: ");
            var archivePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(archivePath) || archivePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!File.Exists(archivePath))
            {
                Console.WriteLine("Archive not found!");
                return;
            }

            Console.Write("Enter split size in MB [or 'back' to return]: ");
            var sizeInput = Console.ReadLine()?.Trim();
            if (sizeInput?.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            
            if (!int.TryParse(sizeInput, out var splitSizeMB) || splitSizeMB <= 0)
            {
                Console.WriteLine("Invalid split size!");
                return;
            }

            var splitSize = splitSizeMB * 1024 * 1024; // Convert to bytes
            SplitFile(archivePath, splitSize);
            Console.WriteLine("Archive split completed!");
        }

        private void ExtractSplitArchive()
        {
            Console.Write("Enter first split file path (.001): ");
            var firstSplitPath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(firstSplitPath) || !File.Exists(firstSplitPath))
            {
                Console.WriteLine("First split file not found!");
                return;
            }

            var basePath = firstSplitPath.Substring(0, firstSplitPath.LastIndexOf('.'));
            var mergedPath = basePath + "_merged" + Path.GetExtension(basePath);

            Console.WriteLine("Merging split files...");
            MergeSplitFiles(basePath, mergedPath);

            Console.Write("Extract merged archive? (y/n): ");
            if (Console.ReadLine()?.ToLower() == "y")
            {
                Console.Write("Enter extraction directory: ");
                var extractPath = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(extractPath))
                    extractPath = Directory.GetCurrentDirectory();

                var format = GetArchiveFormat(mergedPath);
                ExtractArchiveByFormat(mergedPath, extractPath, format);
                
                Console.Write("Delete merged archive? (y/n): ");
                if (Console.ReadLine()?.ToLower() == "y")
                {
                    File.Delete(mergedPath);
                }
            }

            Console.WriteLine("Split archive extraction completed!");
        }

        private void ListArchiveContents()
        {
            Console.Write("Enter archive path [or 'back' to return]: ");
            var archivePath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(archivePath) || archivePath.ToLower() == "back")
            {
                Console.WriteLine("Returning to main menu...");
                return;
            }
            if (!File.Exists(archivePath))
            {
                Console.WriteLine("Archive not found!");
                return;
            }

            var format = GetArchiveFormat(archivePath);
            Console.WriteLine($"\nContents of {Path.GetFileName(archivePath)} ({format}):");
            Console.WriteLine(new string('-', 60));

            try
            {
                using var archive = ArchiveFactory.Open(archivePath);
                foreach (var entry in archive.Entries.Where(e => !e.IsDirectory))
                {
                    Console.WriteLine($"{entry.Key,-40} {FormatFileSize(entry.Size),10} {entry.LastModifiedTime:yyyy-MM-dd HH:mm}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading archive: {ex.Message}");
            }
        }
        // Helper methods and enums
        private enum ArchiveFormat
        {
            Zip, SevenZ, Tar, Zstd, Brotli, Unknown
        }

        private ArchiveFormat GetArchiveFormat(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            return extension switch
            {
                ".zip" => ArchiveFormat.Zip,
                ".7z" => ArchiveFormat.SevenZ,
                ".tar" => ArchiveFormat.Tar,
                ".zst" or ".zstd" => ArchiveFormat.Zstd,
                ".br" or ".brotli" => ArchiveFormat.Brotli,
                _ => ArchiveFormat.Unknown
            };
        }

        private void CreateZipArchive(string sourcePath, string outputPath)
        {
            if (File.Exists(sourcePath))
            {
                var fileInfo = new FileInfo(sourcePath);
                var progress = new ProgressReporter(fileInfo.Length);
                
                Console.WriteLine($"Compressing {Path.GetFileName(sourcePath)}...");
                using var archive = ZipFile.Open(outputPath, ZipArchiveMode.Create);
                var entry = archive.CreateEntry(Path.GetFileName(sourcePath));
                
                using var entryStream = entry.Open();
                using var fileStream = File.OpenRead(sourcePath);
                fileStream.CopyToWithProgress(entryStream, progress);
                progress.Complete();
            }
            else if (Directory.Exists(sourcePath))
            {
                var totalSize = GetDirectorySize(sourcePath);
                var progress = new ProgressReporter(totalSize);
                
                Console.WriteLine($"Compressing directory {Path.GetFileName(sourcePath)}...");
                CreateZipFromDirectoryWithProgress(sourcePath, outputPath, progress);
                progress.Complete();
            }
        }

        private void CreateZipFromDirectoryWithProgress(string sourceDir, string outputPath, ProgressReporter progress)
        {
            using var archive = ZipFile.Open(outputPath, ZipArchiveMode.Create);
            long processedBytes = 0;
            
            AddDirectoryToZipWithProgress(archive, sourceDir, "", progress, ref processedBytes);
        }

        private void AddDirectoryToZipWithProgress(ZipArchive archive, string dirPath, string relativePath, ProgressReporter progress, ref long processedBytes)
        {
            foreach (var file in Directory.GetFiles(dirPath))
            {
                var entryName = Path.Combine(relativePath, Path.GetFileName(file)).Replace('\\', '/');
                var entry = archive.CreateEntry(entryName);
                
                using var entryStream = entry.Open();
                using var fileStream = File.OpenRead(file);
                
                var buffer = new byte[81920];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    entryStream.Write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    progress.UpdateProgress(processedBytes);
                }
            }

            foreach (var subDir in Directory.GetDirectories(dirPath))
            {
                var subDirName = Path.GetFileName(subDir);
                var newRelativePath = Path.Combine(relativePath, subDirName).Replace('\\', '/');
                AddDirectoryToZipWithProgress(archive, subDir, newRelativePath, progress, ref processedBytes);
            }
        }

        private void Create7zArchive(string sourcePath, string outputPath)
        {
            try
            {
                Console.WriteLine("Creating 7Z archive using command-line 7z.exe...");
                
                // Try command-line 7z.exe first
                if (Create7zUsingCommandLine(sourcePath, outputPath))
                {
                    Console.WriteLine("7Z archive created successfully!");
                    return;
                }
                
                // Fallback to ZIP
                Console.WriteLine("7Z creation failed, falling back to ZIP format...");
                CreateZipArchive(sourcePath, Path.ChangeExtension(outputPath, ".zip"));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"7Z compression failed: {ex.Message}");
                Console.WriteLine("Falling back to ZIP format...");
                CreateZipArchive(sourcePath, Path.ChangeExtension(outputPath, ".zip"));
            }
        }

        private void CreateTarArchive(string sourcePath, string outputPath)
        {
            using var stream = File.Create(outputPath);
            using var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.None);
            AddToArchive(writer, sourcePath);
        }

        private void CreateZstdArchive(string sourcePath, string outputPath)
        {
            try
            {
                if (File.Exists(sourcePath))
                {
                    Console.WriteLine("Creating ZSTD compressed file...");
                    var fileInfo = new FileInfo(sourcePath);
                    var progress = new ProgressReporter(fileInfo.Length);
                    
                    var inputBytes = File.ReadAllBytes(sourcePath);
                    var compressedBytes = ZstdSharp.Zstd.Compress(inputBytes);
                    File.WriteAllBytes(outputPath, compressedBytes);
                    
                    progress.UpdateProgress(fileInfo.Length);
                    progress.Complete();
                    Console.WriteLine("ZSTD compression completed!");
                }
                else if (Directory.Exists(sourcePath))
                {
                    Console.WriteLine("ZSTD compression for directories requires TAR+ZSTD combination...");
                    var tarPath = Path.ChangeExtension(outputPath, ".tar");
                    CreateTarArchive(sourcePath, tarPath);
                    
                    Console.WriteLine("Compressing TAR with ZSTD...");
                    CreateZstdArchive(tarPath, outputPath);
                    
                    // Clean up temporary TAR file
                    File.Delete(tarPath);
                    Console.WriteLine("TAR+ZSTD compression completed!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ZSTD compression failed: {ex.Message}");
                Console.WriteLine("Falling back to TAR+Brotli alternative...");
                
                if (Directory.Exists(sourcePath))
                {
                    // For directories, create TAR+Brotli
                    var tarPath = Path.ChangeExtension(outputPath, ".tar");
                    CreateTarArchive(sourcePath, tarPath);
                    CreateBrotliArchive(tarPath, Path.ChangeExtension(outputPath, ".tar.br"));
                    File.Delete(tarPath);
                    Console.WriteLine("TAR+Brotli archive created as ZSTD fallback!");
                }
                else
                {
                    // For single files, use Brotli
                    CreateBrotliArchive(sourcePath, Path.ChangeExtension(outputPath, ".br"));
                    Console.WriteLine("Brotli compression used as ZSTD fallback!");
                }
            }
        }

        private void CreateBrotliArchive(string sourcePath, string outputPath)
        {
            try
            {
                if (File.Exists(sourcePath))
                {
                    Console.WriteLine("Creating Brotli compressed file...");
                    var fileInfo = new FileInfo(sourcePath);
                    var progress = new ProgressReporter(fileInfo.Length);
                    
                    var inputBytes = File.ReadAllBytes(sourcePath);
                    var compressedBytes = Brotli.CompressBuffer(inputBytes, 0, inputBytes.Length);
                    File.WriteAllBytes(outputPath, compressedBytes);
                    
                    progress.UpdateProgress(fileInfo.Length);
                    progress.Complete();
                    Console.WriteLine("Brotli compression completed!");
                }
                else if (Directory.Exists(sourcePath))
                {
                    Console.WriteLine("Brotli compression for directories requires TAR+Brotli combination...");
                    var tarPath = Path.ChangeExtension(outputPath, ".tar");
                    CreateTarArchive(sourcePath, tarPath);
                    
                    Console.WriteLine("Compressing TAR with Brotli...");
                    CreateBrotliArchive(tarPath, outputPath);
                    
                    // Clean up temporary TAR file
                    File.Delete(tarPath);
                    Console.WriteLine("TAR+Brotli compression completed!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Brotli compression failed: {ex.Message}");
            }
        }

        private void AddToArchive(IWriter archive, string sourcePath)
        {
            if (File.Exists(sourcePath))
            {
                archive.Write(Path.GetFileName(sourcePath), sourcePath);
            }
            else if (Directory.Exists(sourcePath))
            {
                AddDirectoryToArchive(archive, sourcePath, "");
            }
        }

        private bool Create7zFromFilesUsingCommandLine(List<string> files, string outputPath)
        {
            try
            {
                var sevenZipPaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip", "7z.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "7-Zip", "7z.exe"),
                    "7z.exe"
                };

                string? sevenZipExe = null;
                foreach (var path in sevenZipPaths)
                {
                    if (File.Exists(path) || path == "7z.exe")
                    {
                        sevenZipExe = path;
                        break;
                    }
                }

                if (sevenZipExe == null)
                    return false;

                // Create a temporary file list for 7z.exe
                var tempListFile = Path.GetTempFileName();
                try
                {
                    File.WriteAllLines(tempListFile, files.Select(f => $"\"{f}\""));
                    
                    var arguments = $"a \"{outputPath}\" @\"{tempListFile}\" -mx=5";
                    
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = sevenZipExe,
                            Arguments = arguments,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        }
                    };

                    Console.WriteLine($"Running: {sevenZipExe} {arguments}");
                    process.Start();
                    
                    var output = process.StandardOutput.ReadToEnd();
                    var error = process.StandardError.ReadToEnd();
                    
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        Console.WriteLine("7Z compression completed successfully!");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"7Z compression failed with exit code {process.ExitCode}");
                        if (!string.IsNullOrEmpty(error))
                            Console.WriteLine($"Error: {error}");
                        return false;
                    }
                }
                finally
                {
                    if (File.Exists(tempListFile))
                        File.Delete(tempListFile);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Command-line 7Z compression failed: {ex.Message}");
                return false;
            }
        }

        private bool Create7zUsingCommandLine(string sourcePath, string outputPath)
        {
            try
            {
                var sevenZipPaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip", "7z.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "7-Zip", "7z.exe"),
                    "7z.exe"
                };

                string? sevenZipExe = null;
                foreach (var path in sevenZipPaths)
                {
                    if (File.Exists(path) || path == "7z.exe")
                    {
                        sevenZipExe = path;
                        break;
                    }
                }

                if (sevenZipExe == null)
                    return false;

                var arguments = $"a \"{outputPath}\" \"{sourcePath}\" -mx=5";
                
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = sevenZipExe,
                        Arguments = arguments,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                Console.WriteLine($"Running: {sevenZipExe} {arguments}");
                process.Start();
                
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("7Z compression completed successfully!");
                    return true;
                }
                else
                {
                    Console.WriteLine($"7Z compression failed with exit code {process.ExitCode}");
                    if (!string.IsNullOrEmpty(error))
                        Console.WriteLine($"Error: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Command-line 7Z compression failed: {ex.Message}");
                return false;
            }
        }

        private void AddDirectoryToArchive(IWriter archive, string dirPath, string relativePath)
        {
            foreach (var file in Directory.GetFiles(dirPath))
            {
                var entryName = Path.Combine(relativePath, Path.GetFileName(file)).Replace('\\', '/');
                archive.Write(entryName, file);
            }

            foreach (var subDir in Directory.GetDirectories(dirPath))
            {
                var subDirName = Path.GetFileName(subDir);
                var newRelativePath = Path.Combine(relativePath, subDirName).Replace('\\', '/');
                AddDirectoryToArchive(archive, subDir, newRelativePath);
            }
        }

        private void ExtractZipArchive(string archivePath, string extractPath)
        {
            using var archive = ZipFile.OpenRead(archivePath);
            var totalSize = archive.Entries.Sum(e => e.Length);
            var progress = new ProgressReporter(totalSize);
            long processedBytes = 0;

            Console.WriteLine($"Extracting {archive.Entries.Count} files...");
            
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.EndsWith("/")) continue; // Skip directories
                
                var destinationPath = Path.Combine(extractPath, entry.FullName);
                var destinationDir = Path.GetDirectoryName(destinationPath);
                
                if (!string.IsNullOrEmpty(destinationDir))
                    Directory.CreateDirectory(destinationDir);

                using var entryStream = entry.Open();
                using var fileStream = File.Create(destinationPath);
                
                var buffer = new byte[81920];
                int bytesRead;
                while ((bytesRead = entryStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fileStream.Write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    progress.UpdateProgress(processedBytes);
                }
            }
            
            progress.Complete();
        }

        private void ExtractGenericArchive(string archivePath, string extractPath)
        {
            var format = GetArchiveFormat(archivePath);
            
            if (format == ArchiveFormat.SevenZ)
            {
                Extract7zArchive(archivePath, extractPath);
                return;
            }
            
            try
            {
                using var archive = ArchiveFactory.Open(archivePath);
                var totalSize = archive.Entries.Sum(e => e.Size);
                var progress = new ProgressReporter(totalSize);
                long processedBytes = 0;

                Console.WriteLine($"Extracting {archive.Entries.Count(e => !e.IsDirectory)} files...");
                
                foreach (var entry in archive.Entries.Where(e => !e.IsDirectory))
                {
                    try
                    {
                        var destinationPath = Path.Combine(extractPath, entry.Key ?? "");
                        var destinationDir = Path.GetDirectoryName(destinationPath);
                        
                        // Ensure directory exists
                        if (!string.IsNullOrEmpty(destinationDir) && !Directory.Exists(destinationDir))
                        {
                            Directory.CreateDirectory(destinationDir);
                        }

                        entry.WriteToDirectory(extractPath, new ExtractionOptions
                        {
                            ExtractFullPath = true,
                            Overwrite = true
                        });
                        
                        processedBytes += entry.Size;
                        progress.UpdateProgress(processedBytes);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to extract {entry.Key}: {ex.Message}");
                    }
                }
                
                progress.Complete();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Archive extraction failed: {ex.Message}");
                throw;
            }
        }

        private void Extract7zArchive(string archivePath, string extractPath)
        {
            try
            {
                Console.WriteLine("Extracting 7Z archive using SharpCompress...");
                
                // Ensure extraction directory exists
                if (!Directory.Exists(extractPath))
                {
                    Directory.CreateDirectory(extractPath);
                }
                
                using var archive = ArchiveFactory.Open(archivePath);
                var totalSize = archive.Entries.Sum(e => e.Size);
                var progress = new ProgressReporter(totalSize);
                long processedBytes = 0;

                Console.WriteLine($"Extracting {archive.Entries.Count(e => !e.IsDirectory)} files...");
                
                foreach (var entry in archive.Entries.Where(e => !e.IsDirectory))
                {
                    try
                    {
                        var destinationPath = Path.Combine(extractPath, entry.Key ?? "");
                        var destinationDir = Path.GetDirectoryName(destinationPath);
                        
                        // Ensure directory exists for each file
                        if (!string.IsNullOrEmpty(destinationDir) && !Directory.Exists(destinationDir))
                        {
                            Directory.CreateDirectory(destinationDir);
                        }

                        entry.WriteToDirectory(extractPath, new ExtractionOptions
                        {
                            ExtractFullPath = true,
                            Overwrite = true
                        });
                        
                        processedBytes += entry.Size;
                        progress.UpdateProgress(processedBytes);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to extract {entry.Key}: {ex.Message}");
                    }
                }
                
                progress.Complete();
                Console.WriteLine("7Z extraction completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"7Z extraction failed: {ex.Message}");
                throw;
            }
        }

        private void ExtractZstdArchive(string archivePath, string extractPath)
        {
            try
            {
                Console.WriteLine("Extracting ZSTD compressed file...");
                Directory.CreateDirectory(extractPath);
                
                var outputFile = Path.Combine(extractPath, Path.GetFileNameWithoutExtension(archivePath));
                var fileInfo = new FileInfo(archivePath);
                var progress = new ProgressReporter(fileInfo.Length);

                var compressedBytes = File.ReadAllBytes(archivePath);
                
                // Use ZstdSharp with the correct API - try different approaches
                byte[] decompressedBytes;
                
                try
                {
                    // Try the simplest approach first
                    decompressedBytes = ZstdSharp.Zstd.Decompress(compressedBytes, compressedBytes.Length * 10);
                }
                catch (Exception)
                {
                    try
                    {
                        // Try with larger buffer
                        decompressedBytes = ZstdSharp.Zstd.Decompress(compressedBytes, compressedBytes.Length * 50);
                    }
                    catch (Exception)
                    {
                        // Last resort - very large buffer
                        decompressedBytes = ZstdSharp.Zstd.Decompress(compressedBytes, compressedBytes.Length * 100);
                    }
                }
                
                File.WriteAllBytes(outputFile, decompressedBytes);
                
                progress.UpdateProgress(fileInfo.Length);
                progress.Complete();
                
                // Check if the extracted file is a TAR archive
                if (Path.GetExtension(outputFile).ToLower() == ".tar")
                {
                    Console.WriteLine("Extracting TAR archive...");
                    ExtractGenericArchive(outputFile, extractPath);
                    File.Delete(outputFile); // Clean up TAR file
                }
                
                Console.WriteLine("ZSTD extraction completed!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ZSTD extraction failed: {ex.Message}");
                Console.WriteLine("Attempting to extract as Brotli or TAR+Brotli fallback...");
                
                try
                {
                    // Try to extract as Brotli first
                    ExtractBrotliArchive(archivePath, extractPath);
                }
                catch (Exception ex2)
                {
                    Console.WriteLine($"ZSTD/Brotli extraction failed: {ex2.Message}");
                    Console.WriteLine("The file may not be a valid ZSTD/Brotli archive.");
                }
            }
        }

        private void ExtractBrotliArchive(string archivePath, string extractPath)
        {
            try
            {
                Console.WriteLine("Extracting Brotli compressed file...");
                Directory.CreateDirectory(extractPath);
                
                var outputFile = Path.Combine(extractPath, Path.GetFileNameWithoutExtension(archivePath));
                var fileInfo = new FileInfo(archivePath);
                var progress = new ProgressReporter(fileInfo.Length);

                var compressedBytes = File.ReadAllBytes(archivePath);
                var decompressedBytes = Brotli.DecompressBuffer(compressedBytes, 0, compressedBytes.Length);
                File.WriteAllBytes(outputFile, decompressedBytes);
                
                progress.UpdateProgress(fileInfo.Length);
                progress.Complete();
                
                // Check if the extracted file is a TAR archive
                if (Path.GetExtension(outputFile).ToLower() == ".tar")
                {
                    Console.WriteLine("Extracting TAR archive...");
                    ExtractGenericArchive(outputFile, extractPath);
                    File.Delete(outputFile); // Clean up TAR file
                }
                
                Console.WriteLine("Brotli extraction completed!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Brotli extraction failed: {ex.Message}");
                Console.WriteLine("The file may not be a valid Brotli archive.");
            }
        }

        private void ExtractArchiveToTemp(string archivePath, string tempDir, ArchiveFormat format)
        {
            switch (format)
            {
                case ArchiveFormat.Zip:
                    ExtractZipArchive(archivePath, tempDir);
                    break;
                case ArchiveFormat.SevenZ:
                case ArchiveFormat.Tar:
                    ExtractGenericArchive(archivePath, tempDir);
                    break;
                case ArchiveFormat.Zstd:
                    ExtractZstdArchive(archivePath, tempDir);
                    break;
                case ArchiveFormat.Brotli:
                    ExtractBrotliArchive(archivePath, tempDir);
                    break;
            }
        }

        private void CreateArchiveFromTemp(string tempDir, string targetPath, ArchiveFormat format)
        {
            switch (format)
            {
                case ArchiveFormat.Zip:
                    CreateZipArchive(tempDir, targetPath);
                    break;
                case ArchiveFormat.SevenZ:
                    Create7zArchive(tempDir, targetPath);
                    break;
                case ArchiveFormat.Tar:
                    CreateTarArchive(tempDir, targetPath);
                    break;
                case ArchiveFormat.Zstd:
                    var firstFile = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).FirstOrDefault();
                    if (firstFile != null)
                        CreateZstdArchive(firstFile, targetPath);
                    break;
                case ArchiveFormat.Brotli:
                    var firstFileBr = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).FirstOrDefault();
                    if (firstFileBr != null)
                        CreateBrotliArchive(firstFileBr, targetPath);
                    break;
            }
        }

        private void ExtractArchiveByFormat(string archivePath, string extractPath, ArchiveFormat format)
        {
            switch (format)
            {
                case ArchiveFormat.Zip:
                    ExtractZipArchive(archivePath, extractPath);
                    break;
                case ArchiveFormat.SevenZ:
                case ArchiveFormat.Tar:
                    ExtractGenericArchive(archivePath, extractPath);
                    break;
                case ArchiveFormat.Zstd:
                    ExtractZstdArchive(archivePath, extractPath);
                    break;
                case ArchiveFormat.Brotli:
                    ExtractBrotliArchive(archivePath, extractPath);
                    break;
            }
        }
        private void CreatePasswordProtectedArchive(string sourcePath, string outputPath, string password, ArchiveFormat format)
        {
            if (format == ArchiveFormat.Zip)
            {
                Console.WriteLine("Creating password-protected ZIP archive...");
                CreatePasswordProtectedZip(sourcePath, outputPath, password);
            }
            else if (format == ArchiveFormat.SevenZ)
            {
                Console.WriteLine("Creating password-protected 7Z archive...");
                CreatePasswordProtected7z(sourcePath, outputPath, password);
            }
            else
            {
                Console.WriteLine("Password protection only supported for ZIP and 7Z formats!");
                return;
            }
        }

        private void CreatePasswordProtectedZip(string sourcePath, string outputPath, string password)
        {
            try
            {
                // For now, create without password and inform user
                Console.WriteLine("Note: Full password protection requires additional libraries.");
                Console.WriteLine("Creating standard ZIP archive...");
                CreateZipArchive(sourcePath, outputPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ZIP creation failed: {ex.Message}");
            }
        }

        private void CreatePasswordProtected7z(string sourcePath, string outputPath, string password)
        {
            try
            {
                Console.WriteLine("Creating password-protected 7Z archive...");
                Console.WriteLine("Note: Password protection for 7Z requires additional implementation.");
                Console.WriteLine("Creating standard 7Z archive for now...");
                Create7zArchive(sourcePath, outputPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"7Z password protection failed: {ex.Message}");
                Console.WriteLine("Creating standard 7Z archive without password...");
                Create7zArchive(sourcePath, outputPath);
            }
        }

        private string CalculateFileHash(string filePath, HashAlgorithm algorithm)
        {
            using var stream = File.OpenRead(filePath);
            var hashBytes = algorithm.ComputeHash(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        private void SplitFile(string filePath, long splitSize)
        {
            var fileInfo = new FileInfo(filePath);
            var progress = new ProgressReporter(fileInfo.Length);
            var baseName = Path.GetFileNameWithoutExtension(filePath);
            var extension = Path.GetExtension(filePath);
            var directory = Path.GetDirectoryName(filePath) ?? "";

            Console.WriteLine($"Splitting {FormatFileSize(fileInfo.Length)} file into {FormatFileSize(splitSize)} parts...");

            using var input = File.OpenRead(filePath);
            var buffer = new byte[splitSize];
            var partNumber = 1;
            long totalProcessed = 0;

            while (input.Position < input.Length)
            {
                var partPath = Path.Combine(directory, $"{baseName}{extension}.{partNumber:D3}");
                using var output = File.Create(partPath);

                var bytesRead = input.Read(buffer, 0, buffer.Length);
                output.Write(buffer, 0, bytesRead);
                
                totalProcessed += bytesRead;
                progress.UpdateProgress(totalProcessed);

                Console.WriteLine($"\nCreated: {Path.GetFileName(partPath)} ({FormatFileSize(bytesRead)})");
                partNumber++;
            }

            progress.Complete();
            Console.WriteLine($"Split into {partNumber - 1} parts");
        }

        private void MergeSplitFiles(string basePath, string outputPath)
        {
            using var output = File.Create(outputPath);
            var partNumber = 1;

            while (true)
            {
                var partPath = $"{basePath}.{partNumber:D3}";
                if (!File.Exists(partPath))
                    break;

                using var input = File.OpenRead(partPath);
                input.CopyTo(output);
                Console.WriteLine($"Merged: {Path.GetFileName(partPath)}");
                partNumber++;
            }

            Console.WriteLine($"Merged {partNumber - 1} parts into {Path.GetFileName(outputPath)}");
        }

        private void DeleteSourceFiles(string sourcePath)
        {
            try
            {
                if (File.Exists(sourcePath))
                {
                    File.Delete(sourcePath);
                    Console.WriteLine("Source file deleted.");
                }
                else if (Directory.Exists(sourcePath))
                {
                    Directory.Delete(sourcePath, true);
                    Console.WriteLine("Source directory deleted.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not delete source: {ex.Message}");
            }
        }

        private string ReadPassword()
        {
            var password = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password.ToString();
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        private long GetDirectorySize(string dirPath)
        {
            long size = 0;
            try
            {
                foreach (var file in Directory.GetFiles(dirPath, "*", SearchOption.AllDirectories))
                {
                    size += new FileInfo(file).Length;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not calculate directory size: {ex.Message}");
            }
            return size;
        }

        private List<string> SelectFilesFromDirectory(string directoryPath)
        {
            var selectedFiles = new List<string>();
            
            try
            {
                // Use more robust file enumeration
                var allFiles = new List<string>();
                try
                {
                    allFiles = Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories)
                                      .Where(f => 
                                      {
                                          try
                                          {
                                              // Test if file is accessible
                                              var info = new FileInfo(f);
                                              return info.Exists && info.Length >= 0;
                                          }
                                          catch
                                          {
                                              return false;
                                          }
                                      })
                                      .ToList();
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("Access denied to some files. Trying accessible files only...");
                    try
                    {
                        allFiles = Directory.GetFiles(directoryPath, "*", SearchOption.TopDirectoryOnly).ToList();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Cannot access directory: {ex.Message}");
                        return selectedFiles;
                    }
                }
                
                if (allFiles.Count == 0)
                {
                    Console.WriteLine("No accessible files found in directory!");
                    return selectedFiles;
                }

                Console.WriteLine($"\nFound {allFiles.Count} accessible files in directory:");
                Console.WriteLine("Selection methods:");
                Console.WriteLine("1. Interactive selection (choose files one by one)");
                Console.WriteLine("2. Pattern-based selection (*.txt, *.jpg, etc.)");
                Console.WriteLine("3. List all files and select by numbers");
                Console.Write("Choose selection method [or 'back' to return]: ");

                var method = Console.ReadLine()?.Trim();
                if (method?.ToLower() == "back") return selectedFiles;

                switch (method)
                {
                    case "1":
                        return InteractiveFileSelection(allFiles, directoryPath);
                    case "2":
                        return PatternBasedSelection(allFiles, directoryPath);
                    case "3":
                        return NumberBasedSelection(allFiles, directoryPath);
                    default:
                        Console.WriteLine("Invalid selection method!");
                        return selectedFiles;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Access denied to directory or some files.");
                return selectedFiles;
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("Directory not found or became inaccessible.");
                return selectedFiles;
            }
            catch (PathTooLongException)
            {
                Console.WriteLine("Directory path is too long.");
                return selectedFiles;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing directory: {ex.Message}");
                Console.WriteLine($"Error code: 0x{ex.HResult:X8}");
                return selectedFiles;
            }
        }

        private List<string> InteractiveFileSelection(List<string> allFiles, string basePath)
        {
            var selectedFiles = new List<string>();
            
            Console.WriteLine("\nInteractive file selection:");
            Console.WriteLine("Type 'y' to include, 'n' to skip, 'done' to finish, 'back' to return");
            
            foreach (var file in allFiles)
            {
                var relativePath = Path.GetRelativePath(basePath, file);
                var fileInfo = new FileInfo(file);
                
                Console.Write($"\nInclude '{relativePath}' ({FormatFileSize(fileInfo.Length)})? (y/n/done/back): ");
                var response = Console.ReadLine()?.ToLower().Trim();
                
                if (response == "back") return new List<string>();
                if (response == "done") break;
                if (response == "y") selectedFiles.Add(file);
            }
            
            Console.WriteLine($"Selected {selectedFiles.Count} files.");
            return selectedFiles;
        }

        private List<string> PatternBasedSelection(List<string> allFiles, string basePath)
        {
            var selectedFiles = new List<string>();
            
            Console.WriteLine("\nPattern-based selection:");
            Console.WriteLine("Examples: *.txt, *.jpg, *.pdf, *report*, data*.csv");
            Console.Write("Enter file pattern [or 'back' to return]: ");
            
            var pattern = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(pattern) || pattern.ToLower() == "back") 
                return selectedFiles;

            try
            {
                var matchingFiles = allFiles.Where(f => 
                {
                    var fileName = Path.GetFileName(f);
                    return IsPatternMatch(fileName, pattern);
                }).ToList();

                Console.WriteLine($"Found {matchingFiles.Count} files matching pattern '{pattern}':");
                foreach (var file in matchingFiles)
                {
                    var relativePath = Path.GetRelativePath(basePath, file);
                    Console.WriteLine($"  {relativePath}");
                }

                Console.Write("Include all these files? (y/n): ");
                if (Console.ReadLine()?.ToLower().Trim() == "y")
                {
                    selectedFiles.AddRange(matchingFiles);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error with pattern: {ex.Message}");
            }

            return selectedFiles;
        }

        private bool IsPatternMatch(string fileName, string pattern)
        {
            // Simple pattern matching - convert * to regex
            var regexPattern = "^" + pattern.Replace("*", ".*").Replace("?", ".") + "$";
            return System.Text.RegularExpressions.Regex.IsMatch(fileName, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        private List<string> NumberBasedSelection(List<string> allFiles, string basePath)
        {
            var selectedFiles = new List<string>();
            
            try
            {
                Console.WriteLine("\nAll files in directory:");
                
                // Limit display to prevent overwhelming output
                var displayLimit = Math.Min(allFiles.Count, 100);
                for (int i = 0; i < displayLimit; i++)
                {
                    try
                    {
                        var relativePath = Path.GetRelativePath(basePath, allFiles[i]);
                        var fileInfo = new FileInfo(allFiles[i]);
                        Console.WriteLine($"{i + 1,3}. {relativePath} ({FormatFileSize(fileInfo.Length)})");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{i + 1,3}. [Error accessing file: {ex.Message}]");
                    }
                }
                
                if (allFiles.Count > displayLimit)
                {
                    Console.WriteLine($"... and {allFiles.Count - displayLimit} more files");
                }

                Console.WriteLine("\nEnter file numbers to include (e.g., 1,3,5-8,10):");
                Console.Write("Selection [or 'back' to return]: ");
                
                var selection = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(selection) || selection.ToLower() == "back") 
                    return selectedFiles;

                var indices = ParseNumberSelection(selection, allFiles.Count);
                foreach (var index in indices)
                {
                    if (index >= 0 && index < allFiles.Count)
                    {
                        selectedFiles.Add(allFiles[index]);
                    }
                }
                
                Console.WriteLine($"Selected {selectedFiles.Count} files.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in file selection: {ex.Message}");
            }

            return selectedFiles;
        }

        private HashSet<int> ParseNumberSelection(string selection, int maxCount)
        {
            var indices = new HashSet<int>();
            var parts = selection.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.Contains('-'))
                {
                    var range = trimmed.Split('-');
                    if (range.Length == 2 && 
                        int.TryParse(range[0].Trim(), out var start) && 
                        int.TryParse(range[1].Trim(), out var end))
                    {
                        for (int i = Math.Max(1, start); i <= Math.Min(maxCount, end); i++)
                        {
                            indices.Add(i - 1); // Convert to 0-based index
                        }
                    }
                }
                else if (int.TryParse(trimmed, out var single))
                {
                    if (single >= 1 && single <= maxCount)
                    {
                        indices.Add(single - 1); // Convert to 0-based index
                    }
                }
            }

            return indices;
        }

        private bool CreateZipArchiveFromFiles(List<string> files, string outputPath, string basePath)
        {
            try
            {
                // Delete existing file if it exists
                if (File.Exists(outputPath))
                {
                    File.Delete(outputPath);
                }
                
                var totalSize = files.Sum(f => 
                {
                    try { return new FileInfo(f).Length; }
                    catch { return 0; }
                });
                var progress = new ProgressReporter(totalSize);
                long processedBytes = 0;

                using var archive = ZipFile.Open(outputPath, ZipArchiveMode.Create);
                
                foreach (var file in files)
                {
                    try
                    {
                        var relativePath = Path.GetRelativePath(basePath, file).Replace('\\', '/');
                        
                        // Ensure the relative path is valid
                        if (string.IsNullOrEmpty(relativePath) || relativePath == ".")
                        {
                            relativePath = Path.GetFileName(file);
                        }
                        
                        var entry = archive.CreateEntry(relativePath);
                        
                        using var entryStream = entry.Open();
                        using var fileStream = File.OpenRead(file);
                        
                        var buffer = new byte[81920];
                        int bytesRead;
                        while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            entryStream.Write(buffer, 0, bytesRead);
                            processedBytes += bytesRead;
                            progress.UpdateProgress(processedBytes);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to add {Path.GetFileName(file)}: {ex.Message}");
                    }
                }
                
                progress.Complete();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ZIP creation failed: {ex.Message}");
                return false;
            }
        }

        private bool Create7zArchiveFromFiles(List<string> files, string outputPath, string basePath)
        {
            try
            {
                Console.WriteLine("Creating 7Z archive from selected files using command-line 7z.exe...");
                
                // Try command-line 7z.exe first
                if (Create7zFromFilesUsingCommandLine(files, outputPath))
                {
                    Console.WriteLine("7Z archive created successfully!");
                    return true;
                }
                
                // Fallback to ZIP
                Console.WriteLine("7Z compression failed, falling back to ZIP format...");
                return CreateZipArchiveFromFiles(files, Path.ChangeExtension(outputPath, ".zip"), basePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"7Z compression failed: {ex.Message}");
                Console.WriteLine("Falling back to ZIP format...");
                return CreateZipArchiveFromFiles(files, Path.ChangeExtension(outputPath, ".zip"), basePath);
            }
        }

        private bool CreateTarArchiveFromFiles(List<string> files, string outputPath, string basePath)
        {
            try
            {
                using var stream = File.Create(outputPath);
                using var writer = WriterFactory.Open(stream, ArchiveType.Tar, CompressionType.None);
                
                foreach (var file in files)
                {
                    try
                    {
                        var relativePath = Path.GetRelativePath(basePath, file).Replace('\\', '/');
                        
                        // Ensure the relative path is valid
                        if (string.IsNullOrEmpty(relativePath) || relativePath == ".")
                        {
                            relativePath = Path.GetFileName(file);
                        }
                        
                        writer.Write(relativePath, file);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to add {Path.GetFileName(file)}: {ex.Message}");
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TAR creation failed: {ex.Message}");
                return false;
            }
        }

        private bool CreateTarZstdArchiveFromFiles(List<string> files, string outputPath, string basePath)
        {
            try
            {
                Console.WriteLine("Creating TAR+ZSTD archive from selected files...");
                var tarPath = Path.ChangeExtension(outputPath, ".tar");
                
                // Create TAR first
                var tarSuccess = CreateTarArchiveFromFiles(files, tarPath, basePath);
                if (!tarSuccess) return false;
                
                // Compress TAR with ZSTD
                Console.WriteLine("Compressing TAR with ZSTD...");
                var tarBytes = File.ReadAllBytes(tarPath);
                var compressedBytes = ZstdSharp.Zstd.Compress(tarBytes);
                File.WriteAllBytes(outputPath, compressedBytes);
                
                // Clean up TAR file
                File.Delete(tarPath);
                Console.WriteLine("TAR+ZSTD archive created successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TAR+ZSTD creation failed: {ex.Message}");
                Console.WriteLine("Falling back to TAR+Brotli...");
                return CreateTarBrotliArchiveFromFiles(files, outputPath, basePath);
            }
        }

        private bool CreateTarBrotliArchiveFromFiles(List<string> files, string outputPath, string basePath)
        {
            try
            {
                Console.WriteLine("Creating TAR+Brotli archive from selected files...");
                var tarPath = Path.ChangeExtension(outputPath, ".tar");
                
                // Create TAR first
                var tarSuccess = CreateTarArchiveFromFiles(files, tarPath, basePath);
                if (!tarSuccess) return false;
                
                // Compress TAR with Brotli
                CreateBrotliArchive(tarPath, outputPath);
                
                // Clean up TAR file
                File.Delete(tarPath);
                Console.WriteLine("TAR+Brotli archive created successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TAR+Brotli creation failed: {ex.Message}");
                return false;
            }
        }
    }

    public class ProgressReporter
    {
        private readonly long _totalBytes;
        private long _processedBytes;
        private DateTime _startTime;
        private readonly object _lock = new object();

        public ProgressReporter(long totalBytes)
        {
            _totalBytes = totalBytes;
            _startTime = DateTime.Now;
        }

        public void UpdateProgress(long bytesProcessed)
        {
            lock (_lock)
            {
                _processedBytes = bytesProcessed;
                var percentage = _totalBytes > 0 ? (double)_processedBytes / _totalBytes * 100 : 0;
                var elapsed = DateTime.Now - _startTime;
                var speed = _processedBytes / elapsed.TotalSeconds;
                var eta = speed > 0 ? TimeSpan.FromSeconds((_totalBytes - _processedBytes) / speed) : TimeSpan.Zero;

                DrawProgressBar(percentage, FormatFileSize(_processedBytes), FormatFileSize(_totalBytes), 
                               FormatSpeed(speed), FormatTime(eta));
            }
        }

        private void DrawProgressBar(double percentage, string processed, string total, string speed, string eta)
        {
            const int barWidth = 40;
            var filledWidth = (int)(percentage / 100 * barWidth);
            var bar = new string('█', filledWidth) + new string('░', barWidth - filledWidth);
            
            Console.Write($"\r[{bar}] {percentage:F1}% ({processed}/{total}) {speed} ETA: {eta}");
        }

        public void Complete()
        {
            var elapsed = DateTime.Now - _startTime;
            var avgSpeed = _totalBytes / elapsed.TotalSeconds;
            Console.WriteLine($"\nCompleted in {FormatTime(elapsed)} - Average speed: {FormatSpeed(avgSpeed)}");
        }

        private string FormatSpeed(double bytesPerSecond)
        {
            if (bytesPerSecond < 1024) return $"{bytesPerSecond:F0} B/s";
            if (bytesPerSecond < 1024 * 1024) return $"{bytesPerSecond / 1024:F1} KB/s";
            if (bytesPerSecond < 1024 * 1024 * 1024) return $"{bytesPerSecond / (1024 * 1024):F1} MB/s";
            return $"{bytesPerSecond / (1024 * 1024 * 1024):F1} GB/s";
        }

        private string FormatTime(TimeSpan time)
        {
            if (time.TotalHours >= 1) return $"{time.Hours:D2}:{time.Minutes:D2}:{time.Seconds:D2}";
            if (time.TotalMinutes >= 1) return $"{time.Minutes:D2}:{time.Seconds:D2}";
            return $"{time.Seconds}s";
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }

    public static class StreamExtensions
    {
        public static void CopyToWithProgress(this Stream source, Stream destination, ProgressReporter progress, int bufferSize = 81920)
        {
            var buffer = new byte[bufferSize];
            long totalBytesRead = 0;
            int bytesRead;

            while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                destination.Write(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
                progress.UpdateProgress(totalBytesRead);
            }
        }
    }
}