namespace Auth.Constants
{
    public class Authorization
    {
        public enum Roles
        {
            Administrator,
            Root,
            User
        }
        

        public const string DefaultUsername = "Root";
        public const string DefaultEmail = "root@System.com";
        public const string DefaultPassword = "SystemRoot2@System.com34532.";
        public const Roles DefaultRole = Roles.User;
    }
}
