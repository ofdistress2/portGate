namespace portGate.Core;

public static class Deployment
{
    public const string PackagedHostName = "portGate.Host.exe";

    // Existing SCM registrations and scheduled tasks refer to this path.
    public const string InstalledHostName = "KnockGate.Host.exe";
    public const string InstallationDirectoryName = "KnockGate";
    public const string ServiceName = "KnockGate";
    public static string InstalledHost => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), InstallationDirectoryName, InstalledHostName);

    public static string CopyPackage(string sourceDirectory, string targetDirectory)
    {
        if (Path.GetFullPath(sourceDirectory).TrimEnd(Path.DirectorySeparatorChar)
            .Equals(Path.GetFullPath(targetDirectory).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            string host = Path.Combine(targetDirectory, InstalledHostName);
            if (!File.Exists(host) || !File.Exists(Path.Combine(targetDirectory, "Templates", "knock.ps1"))) throw new IOException("Поставка неполна.");
            return host;
        }
        using var update = StagePackage(sourceDirectory, targetDirectory);
        string installed = update.Activate();
        update.Commit();
        return installed;
    }

    public static PackageUpdate StagePackage(string sourceDirectory, string targetDirectory)
    {
        string source = Path.GetFullPath(sourceDirectory).TrimEnd(Path.DirectorySeparatorChar);
        string target = Path.GetFullPath(targetDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!File.Exists(Path.Combine(source, PackagedHostName)) || !File.Exists(Path.Combine(source, "Templates", "knock.ps1"))) throw new IOException("Поставка неполна: распакуйте весь ZIP, включая Templates.");
        if (source.Equals(target, StringComparison.OrdinalIgnoreCase)) throw new IOException("Каталог обновления совпадает с каталогом установки.");
        if (target.StartsWith(source + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || source.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Каталоги исходной и установленной поставки не должны быть вложены друг в друга.");
        string manifest = Path.Combine(source, "package-manifest.json");
        if (!File.Exists(manifest)) throw new IOException("Нет package-manifest.json. Распакуйте обновлённую поставку полностью.");
        var entries = Json.Read<List<string>>(File.ReadAllText(manifest));
        if (entries.Count is < 2 or > 2000 || entries.Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Count || !entries.Contains(PackagedHostName) || !entries.Contains("Templates/knock.ps1")) throw new IOException("Некорректный список файлов поставки.");
        var files = new List<(string Source, string Relative)>();
        foreach (string relative in entries.Append("package-manifest.json"))
        {
            string file = Path.GetFullPath(Path.Combine(source, relative));
            if (Path.IsPathRooted(relative) || !file.StartsWith(source + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Путь выходит за пределы поставки.");
            if (!File.Exists(file)) throw new IOException("Отсутствует файл поставки: " + relative);
            for (string? current = file; current != null && current.StartsWith(source, StringComparison.OrdinalIgnoreCase); current = Path.GetDirectoryName(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в поставке не поддерживаются.");
            string packagePath = Path.GetRelativePath(source, file);
            string installedPath = packagePath.Equals(PackagedHostName, StringComparison.OrdinalIgnoreCase)
                ? InstalledHostName
                : packagePath;
            files.Add((file, installedPath));
        }
        string staging = target + ".stage-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(staging);
        try
        {
            foreach (var file in files)
            {
                string staged = Path.Combine(staging, file.Relative);
                Directory.CreateDirectory(Path.GetDirectoryName(staged)!);
                File.Copy(file.Source, staged);
            }
            var installedEntries = files.Select(file => file.Relative.Replace('\\', '/'))
                .Where(relative => relative != "package-manifest.json").ToArray();
            File.WriteAllText(Path.Combine(staging, "package-manifest.json"), Json.Write(installedEntries));
            return new PackageUpdate(target, staging, files.Select(file => file.Relative).ToArray());
        }
        catch
        {
            Directory.Delete(staging, recursive: true);
            throw;
        }
    }

    public sealed class PackageUpdate(string target, string staging, string[] files) : IDisposable
    {
        private readonly string backup = target + ".previous-" + Guid.NewGuid().ToString("N");
        private bool activated;

        public string Activate()
        {
            if (Directory.Exists(target))
            {
                if ((File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0) throw new IOException("Каталог установки не может быть ссылкой.");
                foreach (string relative in files)
                {
                    string installed = Path.Combine(target, relative);
                    if (!File.Exists(installed)) continue;
                    for (string? path = installed; path != null && path.Length > target.Length; path = Path.GetDirectoryName(path))
                        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в каталоге установки не поддерживаются.");
                    try { using var probe = new FileStream(installed, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
                    catch (IOException e) { throw new IOException("Файлы установленной версии заняты. Закройте старую панель и команды portGate.", e); }
                }
                Directory.Move(target, backup);
            }
            try
            {
                Directory.Move(staging, target);
                activated = true;
                return Path.Combine(target, InstalledHostName);
            }
            catch { Rollback(); throw; }
        }

        public void Commit()
        {
            activated = false;
            DeleteGeneratedDirectory(backup);
        }

        public void Rollback()
        {
            if (activated) Directory.Move(target, staging);
            activated = false;
            if (Directory.Exists(backup)) Directory.Move(backup, target);
        }

        public void Dispose() => DeleteGeneratedDirectory(staging);

        private static void DeleteGeneratedDirectory(string path)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Trace.TraceWarning("portGate: не удалось удалить каталог {0}: {1}", path, e.Message);
            }
        }
    }
}
