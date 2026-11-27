using System.Drawing.Drawing2D;

namespace portGate.Manager;

internal static class Theme
{
    public static Color Canvas => Pick(0xF3F4F6, SystemColors.Control);
    public static Color Surface => Pick(0xFFFFFF, SystemColors.Window);
    public static Color Subtle => Pick(0xF9FAFB, SystemColors.Control);
    public static Color Border => Pick(0xE5E7EB, SystemColors.WindowText);
    public static Color Text => Pick(0x111827, SystemColors.WindowText);
    public static Color Secondary => Pick(0x4B5563, SystemColors.WindowText);
    public static Color Muted => Pick(0x6B7280, SystemColors.WindowText);
    public static Color Accent => Pick(0x2563EB, SystemColors.Highlight);
    public static Color AccentSoft => Pick(0xEFF6FF, SystemColors.Window);
    public static Font Body { get; } = new("Segoe UI", 9.5f);
    public static Font Heading { get; } = new("Segoe UI", 15, FontStyle.Bold);
    public static Font CardTitle { get; } = new("Segoe UI", 10.5f, FontStyle.Bold);
    public static Font Mono { get; } = new("Consolas", 9.5f);
    public static Color Pick(int rgb, Color fallback) => SystemInformation.HighContrast ? fallback :
        Color.FromArgb((int)(0xff000000u | (uint)rgb));
    public static GraphicsPath Rounded(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        int diameter = Math.Min(radius * 2, Math.Min(rect.Width, rect.Height));
        if (diameter < 2) { path.AddRectangle(rect); return path; }
        path.AddArc(rect.Left, rect.Top, diameter, diameter, 180, 90);
        path.AddArc(rect.Right - diameter, rect.Top, diameter, diameter, 270, 90);
        path.AddArc(rect.Right - diameter, rect.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(rect.Left, rect.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }
}

internal sealed class CardPanel : Panel
{
    public CardPanel()
    {
        DoubleBuffered = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        BackColor = Theme.Surface;
        Padding = new Padding(16);
        Margin = new Padding(0);
    }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor ?? Theme.Canvas);
        if (Width < 2 || Height < 2) return;
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var path = Theme.Rounded(rect, 8 * DeviceDpi / 96);
        using var brush = new SolidBrush(BackColor);
        using var border = new Pen(Theme.Border);
        e.Graphics.FillPath(brush, path);
        e.Graphics.DrawPath(border, path);
    }
}

internal enum ActionStyle { Primary, Secondary, DangerOutline, Ghost }

internal class ActionButton : Button
{
    public override Size GetPreferredSize(Size proposedSize)
    {
        var textSize = TextRenderer.MeasureText(Text, Font);
        int border = Math.Max(4, 6 * DeviceDpi / 96);
        return new Size(base.GetPreferredSize(proposedSize).Width, textSize.Height + Padding.Vertical + border);
    }

    public ActionButton(ActionStyle style = ActionStyle.Secondary)
    {
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(6, 2, 6, 2);
        Margin = new Padding(0, 2, 6, 2);
        if (SystemInformation.HighContrast) return;
        FlatStyle = FlatStyle.Flat;
        ForeColor = style switch
        {
            ActionStyle.Primary => Color.White,
            ActionStyle.DangerOutline => Color.FromArgb(0xDC, 0x26, 0x26),
            _ => Theme.Text
        };
        BackColor = style == ActionStyle.Primary ? Theme.Accent : Theme.Surface;
        FlatAppearance.BorderColor = style switch
        {
            ActionStyle.Primary => Theme.Accent,
            ActionStyle.DangerOutline => Color.FromArgb(0xFC, 0xA5, 0xA5),
            _ => Color.FromArgb(0xD1, 0xD5, 0xDB)
        };
        FlatAppearance.BorderSize = style == ActionStyle.Ghost ? 0 : 1;
        FlatAppearance.MouseOverBackColor = style switch
        {
            ActionStyle.Primary => Color.FromArgb(0x1D, 0x4E, 0xD8),
            ActionStyle.DangerOutline => Color.FromArgb(0xFE, 0xF2, 0xF2),
            _ => Theme.AccentSoft
        };
        EnabledChanged += (_, _) =>
        {
            if (style != ActionStyle.Primary) return;
            BackColor = Enabled ? Theme.Accent : Theme.Subtle;
            FlatAppearance.BorderColor = Enabled ? Theme.Accent : Theme.Border;
        };
    }
}

internal sealed class NavButton : ActionButton
{
    private bool active;
    private int? count;

    public NavButton(string caption) : base(ActionStyle.Ghost)
    {
        Text = caption;
        AutoSize = false;
        Height = 42;
        Dock = DockStyle.Top;
        TextAlign = ContentAlignment.MiddleLeft;
        Padding = new Padding(12, 0, 12, 0);
    }

    public void SetActive(bool selected)
    {
        active = selected;
        BackColor = selected ? (SystemInformation.HighContrast ? SystemColors.Highlight : Theme.AccentSoft) : Theme.Surface;
        ForeColor = selected ? Theme.Pick(0x1D4ED8, SystemColors.HighlightText) : Theme.Text;
        Invalidate();
    }

    public void SetCount(int value)
    {
        count = value;
        AccessibleName = $"{Text} ({value})";
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs pevent)
    {
        base.OnPaint(pevent);
        if (active)
        {
            using var brush = new SolidBrush(SystemInformation.HighContrast ? SystemColors.HighlightText : Theme.Accent);
            pevent.Graphics.FillRectangle(brush, 0, 0, Math.Max(1, 3 * DeviceDpi / 96), Height);
        }
        if (count is { } value)
        {
            var area = new Rectangle(Width - 62 * DeviceDpi / 96, 0, 52 * DeviceDpi / 96, Height);
            StatusPill.Paint(pevent.Graphics, area, value.ToString(), Font, PillTone.Neutral);
        }
    }
}

internal enum PillTone { Neutral, Good, Warning, Error }

internal sealed class StatusLabel : Label
{
    private PillTone tone;

    public StatusLabel(string caption)
    {
        Text = caption;
        AutoSize = true;
        Padding = new Padding(11, 4, 11, 4);
    }

    public void SetTone(PillTone value)
    {
        tone = value;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (SystemInformation.HighContrast) base.OnPaint(e);
        else StatusPill.Paint(e.Graphics, ClientRectangle, Text, Font, tone);
    }
}

internal static class StatusPill
{
    public static void Paint(Graphics graphics, Rectangle area, string text, Font font, PillTone tone)
    {
        if (area.Width < 8 || area.Height < 8 || text.Length == 0) return;
        var colors = tone switch
        {
            PillTone.Good => (0x15803D, 0xDCFCE7, 0x86EFAC),
            PillTone.Warning => (0xB45309, 0xFEF3C7, 0xFCD34D),
            PillTone.Error => (0xDC2626, 0xFEF2F2, 0xFCA5A5),
            _ => (0x4B5563, 0xF9FAFB, 0xE5E7EB)
        };
        var size = TextRenderer.MeasureText(graphics, text, font);
        int inset = Math.Max(3, (int)(5 * graphics.DpiX / 96));
        var pill = new Rectangle(area.X + inset, area.Y + (area.Height - size.Height - 4) / 2,
            Math.Min(area.Width - inset * 2, size.Width + inset * 2), Math.Min(area.Height - 2, size.Height + 4));
        if (pill.Width <= 0 || pill.Height <= 0) return;
        var oldSmoothing = graphics.SmoothingMode;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var path = Theme.Rounded(pill, pill.Height / 2);
        using var back = new SolidBrush(Theme.Pick(colors.Item2, SystemColors.Window));
        using var border = new Pen(Theme.Pick(colors.Item3, SystemColors.WindowText));
        graphics.FillPath(back, path);
        graphics.DrawPath(border, path);
        graphics.SmoothingMode = oldSmoothing;
        TextRenderer.DrawText(graphics, text, font, pill, Theme.Pick(colors.Item1, SystemColors.WindowText),
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }
}

internal static class GridStyler
{
    public static DataGridView Create()
    {
        var grid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, MultiSelect = false, AllowUserToAddRows = false,
            AllowUserToDeleteRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, BorderStyle = BorderStyle.None,
            CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal, GridColor = Theme.Border,
            BackgroundColor = Theme.Surface, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None,
            EnableHeadersVisualStyles = false, ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
            ColumnHeadersHeight = 38, Margin = new Padding(0)
        };
        grid.RowTemplate.Height = 36;
        void ScaleHeights()
        {
            int rowHeight = 36 * grid.DeviceDpi / 96;
            grid.ColumnHeadersHeight = 38 * grid.DeviceDpi / 96;
            grid.RowTemplate.MinimumHeight = rowHeight;
            grid.RowTemplate.Height = rowHeight;
            foreach (DataGridViewRow row in grid.Rows)
            {
                row.MinimumHeight = rowHeight;
                if (grid.AutoSizeRowsMode == DataGridViewAutoSizeRowsMode.None) row.Height = rowHeight;
            }
        }
        grid.HandleCreated += (_, _) => ScaleHeights();
        grid.DpiChangedAfterParent += (_, _) => ScaleHeights();
        grid.DefaultCellStyle.BackColor = Theme.Surface;
        grid.DefaultCellStyle.ForeColor = Theme.Text;
        grid.DefaultCellStyle.SelectionBackColor = Theme.Pick(0xEFF6FF, SystemColors.Highlight);
        grid.DefaultCellStyle.SelectionForeColor = Theme.Pick(0x111827, SystemColors.HighlightText);
        grid.DefaultCellStyle.Padding = new Padding(5, 0, 5, 0);
        grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Subtle;
        grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Secondary;
        grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Subtle;
        grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = Theme.Secondary;
        grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(5, 0, 5, 0);
        return grid;
    }

    public static void PaintPills(DataGridView grid, string column, Func<int, PillTone> tone)
    {
        grid.CellPainting += (_, e) =>
        {
            if (SystemInformation.HighContrast || e.RowIndex < 0 || e.ColumnIndex < 0 ||
                grid.Columns[e.ColumnIndex].Name != column || e.Graphics == null) return;
            e.Paint(e.ClipBounds, DataGridViewPaintParts.All & ~DataGridViewPaintParts.ContentForeground);
            StatusPill.Paint(e.Graphics, e.CellBounds, "● " + e.FormattedValue, grid.Font, tone(e.RowIndex));
            e.Handled = true;
        };
    }
}

internal sealed class ShieldMark : Control
{
    public ShieldMark() => Size = new Size(34, 36);
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        e.Graphics.ScaleTransform(Width / 34f, Height / 36f);
        using var fill = new SolidBrush(Theme.Accent);
        e.Graphics.FillPolygon(fill, [new Point(17, 1), new(31, 6), new(30, 21), new(25, 29), new(17, 35), new(9, 29), new(4, 21), new(3, 6)]);
        using var check = new Pen(Theme.Pick(0xFFFFFF, SystemColors.HighlightText), 2.5f);
        e.Graphics.DrawLines(check, [new Point(10, 17), new(15, 22), new(24, 12)]);
    }
}
