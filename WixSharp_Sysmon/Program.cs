using System;
using WixSharp;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.IO;
using System.Linq;
using System.Net;
using Microsoft.Deployment.WindowsInstaller;
using WixSharp.CommonTasks;

namespace WixSharpSysmon
{
    class Program
    {
        static string DownloadFile(Uri remoteURL, string folder = null, string filename = null)
        {

            if (folder == null)
            {
                folder = System.IO.Path.GetTempPath();
            }
            if (filename == null)
            {
                filename = System.IO.Path.GetRandomFileName();
            }

            string FullFileName = System.IO.Path.Combine(folder, filename);

           
            System.Net.WebClient webDownloader = new System.Net.WebClient();
            Console.WriteLine("Downloading File \"{0}\" to \"{1}\" ...", remoteURL, FullFileName);
            webDownloader.DownloadFile(remoteURL, FullFileName);

            return FullFileName;

        }

        static Project CreateProject(Platform pt, string srcPath, Version ver)
        {
            var project = new ManagedProject()
            {

                LicenceFile = Path.Combine(Directory.GetCurrentDirectory(), "Disclaimer.rtf"),
                OutDir=  Path.Combine(Directory.GetCurrentDirectory(), "output"),
                SourceBaseDir = srcPath,
                Version = ver,
                ControlPanelInfo = new ProductInfo()
                {
                    Manufacturer = "1Dimitri",
                    UrlInfoAbout = "https://github.com/1Dimitri/WixSharpSysMon"
                },
                Platform = pt
            };

            string shortArch;
            string longArch;
            string sysmonFile;
            switch (pt)
            {
                case Platform.x86:
                    shortArch = "x86";
                    longArch = "32-bit";
                    project.GUID = new Guid("34706202-4E79-4F86-99CA-9CF957A69BB5");
                    sysmonFile = "sysmon.exe";
                    break;
                case Platform.x64:
                    shortArch = "x64";
                    longArch = "64-bit";
                    project.GUID = new Guid("E42C5D33-F073-48A6-AFAB-29A3A1EDE4D1");
                    sysmonFile = "sysmon64.exe";
                    break;
                default:
                    throw new NotImplementedException("Unsupported architecture");
            };

            project.Name = $"Sysmon with Config {ver} ({longArch})";
            project.OutFileName = $"Sysmon_With_Config_{ver}_{shortArch}";
            project.Dirs = new Dir[]
            {
                new Dir(@"%ProgramFiles%\1Dimitri\Sysmon",
                new WixSharp.File(/*new Id("sysmon_exe"),*/sysmonFile),
                new WixSharp.File("sysmonconfig-export.xml")// not used with custom action:,
                //new WixSharp.File(new Id("install"),Path.Combine(Directory.GetCurrentDirectory(),"install.cmd")),
                //new WixSharp.File(new Id("uninstall"),Path.Combine(Directory.GetCurrentDirectory(),"uninstall.cmd"))


               )
            };
            project.Properties = new Property[]
            {
                new Property("SysmonPath",$"{sysmonFile}"),
                new Property("DataFile",$"sysmonconfig-export.xml")
            };
            
            
            project.Actions = new[] {
                // Using this creates elevation issue and quotes parsing prolms
            //    //new InstalledFileAction("sysmon_exe", @"-accepteula -i [INSTALLDIR]sysmonconfig-export.xml", Return.check, When.After, Step.InstallFiles, Condition.NOT_Installed),
            //    // new InstalledFileAction("sysmon_exe", "-u", Return.check, When.Before, Step.RemoveFiles, Condition.Installed)
            
            new ElevatedManagedAction(Custom.Install,Return.check,When.After,Step.InstallFiles,Condition.NOT_Installed) { UsesProperties = "SysmonPath,DataFile"},
            new ElevatedManagedAction(Custom.Uninstall,Return.check,When.Before,Step.RemoveFiles,Condition.Installed) { UsesProperties = "SysmonPath,DataFile" }
             };

            project.InstallPrivileges = InstallPrivileges.elevated;

            
            return project;

        }
        static void Main()
        {
            // TLS 1.2 at least required by Github in 2020. Expecting sysinternals.com t some point too.
            // Not sure if the .NET Framework we are running on encompasses it, so...
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

            // Get sysmon.exe & sysmon64.exe
            Uri sysmonUri = new Uri(@"https://download.sysinternals.com/files/Sysmon.zip");

            string zipFile = DownloadFile(sysmonUri);


            string zipDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.IO.Path.GetRandomFileName());
            Console.WriteLine("Extracting File \"{0}\" to \"{1}\" .......\n\n", zipFile, zipDir);
            ZipFile.ExtractToDirectory(zipFile, zipDir);

            // Get sysmon-config.xml
           
            Uri configXMLUri = new Uri(@"https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml");
            string configFile = DownloadFile(configXMLUri, zipDir,"sysmonconfig-export.xml");
           
            // get higher date between sysmon and configuration file
            Match m = Regex.Match(System.IO.File.ReadAllText(configFile), @"Date: (\d{4}-\d{2}-\d{2})");
            DateTime dtConfig;
            if (m.Success)
            {
                DateTime.TryParse(m.Groups[1].Value, out dtConfig);
                Console.WriteLine("Date found in sysmonconfig-export.xml is {0}", dtConfig);
            }
            else
            {
                dtConfig = new DateTime(DateTime.MinValue.Ticks);
                Console.WriteLine("Date not found in sysmonconfig-export.xml, initializing with {0}", dtConfig);
            }

            DirectoryInfo directory = new DirectoryInfo(zipDir);
            FileInfo newestFile = directory.GetFiles().Where(s => s.Name.StartsWith("Sysmon")).OrderByDescending(f => f.LastWriteTime).First();
            DateTime dtFile = newestFile.LastWriteTimeUtc;
            Console.WriteLine("Newest file is {0}, with Date {1}", newestFile.Name, dtFile);
            DateTime ConfigOrSysmon = new[] { dtFile, dtConfig }.Max();
            string strVersion = ConfigOrSysmon.ToString("yy.MM.dd");
            Version sysmonPkgVersion = new Version(strVersion);
            Console.WriteLine("Computed Version {0}", sysmonPkgVersion);

            // and now Repack files as msi
            var projectx86 = CreateProject(Platform.x86, zipDir, sysmonPkgVersion);
            Compiler.BuildMsi(projectx86);

            var projectx64 = CreateProject(Platform.x64, zipDir, sysmonPkgVersion);
            Compiler.BuildMsi(projectx64);
            // clean-up temporary files
            System.IO.File.Delete(zipFile);
            System.IO.Directory.Delete(zipDir, true);


        }

        
    }

    public class Custom { 
    
        [CustomAction]
        public static ActionResult Install(Session session)
        {   
            return session.HandleErrors(
                ()=> RunSysmon(true, Path.Combine(session.Property("INSTALLDIR"), session.Property("SysmonPath")), Path.Combine(session.Property("INSTALLDIR"), session.Property("DataFile")))
                );
        }

        private static int RunSysmon(bool isInstalling,string exePath,string datafilePath)
        {
            var sysmon = new ExternalTool
            {
                ExePath = exePath,
                Arguments = isInstalling ? $"-accepteula -i \"{datafilePath}\"" : "-u"
                
            };
            
            return sysmon.ConsoleRun();
          
        }

        [CustomAction]
        public static ActionResult Uninstall(Session session)
        {
            return session.HandleErrors(
                () => RunSysmon(false, Path.Combine(session.Property("INSTALLDIR"),session.Property("SysmonPath")), Path.Combine(session.Property("INSTALLDIR"),session.Property("DataFile")))
                );
        }
    
    }
}