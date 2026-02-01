namespace RealCordinator.Api.Services
{
    public static class TempUserStore
    {
        private static readonly Dictionary<string, (string Password, string MemberType, string Code)> _users
            = new();

        public static void Save(string email, string password, string memberType, string code)
        {
            _users[email] = (password, memberType, code);
        }

        public static bool Validate(
            string email,
            string code,
            out string password,
            out string memberType)
        {
            password = null!;
            memberType = null!;

            if (!_users.ContainsKey(email)) return false;

            var data = _users[email];
            if (data.Code != code) return false;

            password = data.Password;
            memberType = data.MemberType;

            _users.Remove(email);
            return true;
        }
    }
}
