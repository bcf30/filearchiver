using Microsoft.AspNetCore.Mvc;

namespace ConsoleApp1.Controllers;

public class HomeController : Controller
{
    private readonly CompressionService _service = new();

    public IActionResult Index() => View();

    [HttpPost]
    public async Task<IActionResult> Compress(IFormFile file, string format)
    {
        if (file == null || file.Length == 0) return BadRequest("no file");

        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(file.FileName));
        var outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + "." + GetProperExtension(format));

        try
        {
            using (var fileStream = System.IO.File.Create(tempPath))
            {
                await file.CopyToAsync(fileStream);
                await fileStream.FlushAsync();
            }

            await Task.Delay(100);

            _service.CompressFile(tempPath, outputPath, format, file.FileName);
            
            var fileBytes = await System.IO.File.ReadAllBytesAsync(outputPath);
            var fileName = Path.GetFileNameWithoutExtension(file.FileName) + "." + GetProperExtension(format);
            var mimeType = GetMimeType(fileName);

            Response.Headers["Content-Disposition"] = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}";
            Response.Headers["Content-Type"] = mimeType;
            Response.Headers["X-Suggested-Filename"] = fileName;
            
            return File(fileBytes, mimeType, fileName);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            await Task.Delay(50);
            for (int i = 0; i < 3; i++)
            {
                try 
                { 
                    if (System.IO.File.Exists(tempPath)) 
                    {
                        System.IO.File.Delete(tempPath);
                        break;
                    }
                } 
                catch 
                { 
                    if (i == 2) break;
                    await Task.Delay(100);
                }
            }
            
            for (int i = 0; i < 3; i++)
            {
                try 
                { 
                    if (System.IO.File.Exists(outputPath)) 
                    {
                        System.IO.File.Delete(outputPath);
                        break;
                    }
                } 
                catch 
                { 
                    if (i == 2) break;
                    await Task.Delay(100);
                }
            }
        }
    }

    [HttpPost]
    public async Task<IActionResult> CompressMultiple(List<IFormFile> files, string format)
    {
        if (files == null || files.Count == 0) return BadRequest("no files");

        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + "." + GetProperExtension(format));

        try
        {
            Directory.CreateDirectory(tempDir);

            foreach (var file in files)
            {
                var filePath = Path.Combine(tempDir, file.FileName);
                
                // Create directory structure if needed (for folder uploads)
                var fileDir = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(fileDir) && !Directory.Exists(fileDir))
                {
                    Directory.CreateDirectory(fileDir);
                }
                
                using (var stream = System.IO.File.Create(filePath))
                    await file.CopyToAsync(stream);
            }

            _service.CompressDirectory(tempDir, outputPath, format);
            var fileBytes = await System.IO.File.ReadAllBytesAsync(outputPath);
            var fileName = $"archive.{GetProperExtension(format)}";
            var mimeType = GetMimeType(fileName);

            Response.Headers["Content-Disposition"] = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}";
            Response.Headers["Content-Type"] = mimeType;
            Response.Headers["X-Suggested-Filename"] = fileName;

            return File(fileBytes, mimeType, fileName);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
            try { if (System.IO.File.Exists(outputPath)) System.IO.File.Delete(outputPath); } catch { }
        }
    }

    [HttpPost]
    public async Task<IActionResult> Extract(IFormFile file)
    {
        if (file == null || file.Length == 0) return BadRequest("no file");

        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(file.FileName));
        var extractDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        try
        {
            using (var stream = System.IO.File.Create(tempPath))
                await file.CopyToAsync(stream);

            Directory.CreateDirectory(extractDir);
            _service.ExtractFile(tempPath, extractDir);

            var files = Directory.GetFiles(extractDir, "*", SearchOption.AllDirectories);
            Console.WriteLine($"DEBUG: Controller found {files.Length} files after extraction");
            foreach (var f in files)
            {
                Console.WriteLine($"DEBUG: Found file: {Path.GetFileName(f)}");
            }
            
            if (files.Length == 1)
            {
                var fileBytes = await System.IO.File.ReadAllBytesAsync(files[0]);
                var fileName = Path.GetFileName(files[0]);
                var mimeType = GetMimeType(fileName);
                
                Response.Headers["Content-Disposition"] = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}";
                Response.Headers["Content-Type"] = mimeType;
                Response.Headers["X-Suggested-Filename"] = fileName;
                
                return File(fileBytes, mimeType, fileName);
            }
            else
            {
                var fileList = new List<object>();
                foreach (var filePath in files)
                {
                    var fileName = Path.GetRelativePath(extractDir, filePath);
                    var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
                    fileList.Add(new { 
                        name = fileName, 
                        data = System.Convert.ToBase64String(fileBytes),
                        size = fileBytes.Length
                    });
                }

                var zipPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".zip");
                System.IO.Compression.ZipFile.CreateFromDirectory(extractDir, zipPath);
                var zipBytes = await System.IO.File.ReadAllBytesAsync(zipPath);
                
                try { System.IO.File.Delete(zipPath); } catch { }
                
                return Json(new { 
                    files = fileList, 
                    message = "multiple files extracted",
                    zipData = System.Convert.ToBase64String(zipBytes),
                    zipName = "all_extracted_files.zip"
                });
            }
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            try { if (System.IO.File.Exists(tempPath)) System.IO.File.Delete(tempPath); } catch { }
            try { if (Directory.Exists(extractDir)) Directory.Delete(extractDir, true); } catch { }
        }
    }

    [HttpPost]
    public async Task<IActionResult> Convert(IFormFile file, string targetFormat)
    {
        if (file == null || file.Length == 0) return BadRequest("no file");

        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(file.FileName));
        var extractDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + "." + GetProperExtension(targetFormat));

        try
        {
            using (var stream = System.IO.File.Create(tempPath))
                await file.CopyToAsync(stream);

            Directory.CreateDirectory(extractDir);
            _service.ExtractFile(tempPath, extractDir);
            _service.CompressDirectory(extractDir, outputPath, targetFormat);

            var fileBytes = await System.IO.File.ReadAllBytesAsync(outputPath);
            var fileName = Path.GetFileNameWithoutExtension(file.FileName) + "." + GetProperExtension(targetFormat);
            var mimeType = GetMimeType(fileName);

            Response.Headers["Content-Disposition"] = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}";
            Response.Headers["Content-Type"] = mimeType;

            return File(fileBytes, mimeType, fileName);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            try { if (System.IO.File.Exists(tempPath)) System.IO.File.Delete(tempPath); } catch { }
            try { if (System.IO.File.Exists(outputPath)) System.IO.File.Delete(outputPath); } catch { }
            try { if (Directory.Exists(extractDir)) Directory.Delete(extractDir, true); } catch { }
        }
    }

    [HttpPost]
    public async Task<IActionResult> Hash(IFormFile file, string algorithm)
    {
        if (file == null || file.Length == 0) return BadRequest("no file");

        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(file.FileName));

        try
        {
            using (var stream = System.IO.File.Create(tempPath))
                await file.CopyToAsync(stream);

            var hash = _service.CalculateHash(tempPath, algorithm);

            return Json(new { hash });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            try { if (System.IO.File.Exists(tempPath)) System.IO.File.Delete(tempPath); } catch { }
        }
    }

    [HttpPost]
    public async Task<IActionResult> VerifyHash(IFormFile file, string algorithm, string expectedHash)
    {
        if (file == null || file.Length == 0) return BadRequest("no file");
        if (string.IsNullOrEmpty(expectedHash)) return BadRequest("hash required");

        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(file.FileName));

        try
        {
            using (var stream = System.IO.File.Create(tempPath))
                await file.CopyToAsync(stream);

            var isValid = _service.VerifyHash(tempPath, expectedHash, algorithm);
            var actualHash = _service.CalculateHash(tempPath, algorithm);

            return Json(new { valid = isValid, expected = expectedHash, actual = actualHash });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
        finally
        {
            try { if (System.IO.File.Exists(tempPath)) System.IO.File.Delete(tempPath); } catch { }
        }
    }

    private static string GetProperExtension(string format)
    {
        return format.ToLower() switch
        {
            "zst" => "tar.zst",
            "zstd" => "tar.zst", 
            "br" => "tar.br",
            "brotli" => "tar.br",
            _ => format
        };
    }

    private static string GetMimeType(string fileName)
    {
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        return extension switch
        {
            ".zip" => "application/zip",
            ".7z" => "application/x-7z-compressed", 
            ".tar" => "application/x-tar",
            ".zst" => "application/x-zstd",
            ".zstd" => "application/x-zstd", 
            ".br" => "application/x-brotli",
            ".brotli" => "application/x-brotli",
            ".txt" => "text/plain",
            ".pdf" => "application/pdf",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".mp4" => "video/mp4",
            ".mp3" => "audio/mpeg",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _ => fileName.EndsWith(".tar.zst") ? "application/x-zstd" :
                 fileName.EndsWith(".tar.br") ? "application/x-brotli" :
                 "application/octet-stream"
        };
    }
}