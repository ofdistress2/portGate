namespace portGate.Manager;
internal static class Program
{
    [STAThread] private static void Main()
    {
        ApplicationConfiguration.Initialize();
        bool showSettings = false;
        do
        {
            using var panel = new MainForm(showSettings);
            Application.Run(panel);
            showSettings = panel.LanguageChanged;
        } while (showSettings);
    }
}
