using System.Text;

namespace SecureLab.Api.Security;

// Недовірений текст перед записом у журнал: без керувальних символів (CR/LF тощо)
// і з обмеженою довжиною, щоб користувач не міг "дописати" фальшивий рядок журналу.
public static class LogText
{
    public static string Safe(string? value, int maxLength = 64)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(Math.Min(value.Length, maxLength));
        foreach (var character in value)
        {
            if (builder.Length >= maxLength)
            {
                break;
            }

            builder.Append(char.IsControl(character) ? '_' : character);
        }

        return builder.ToString();
    }
}
