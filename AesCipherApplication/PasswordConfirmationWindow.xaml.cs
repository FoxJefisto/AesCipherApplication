using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AesCipherApplication
{
    /// <summary>
    /// Логика взаимодействия для KeyConfirmationWindow.xaml
    /// </summary>
    public partial class PasswordConfirmationWindow : Window
    {
        string Key { get; set; }
        public PasswordConfirmationWindow()
        {
            InitializeComponent();
        }

        public PasswordConfirmationWindow(string key) : this()
        {
            this.Key = key;
        }

        private void btnConfirm_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = pbKey.Password == Key;
        }

        private void btnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult=false;
        }
    }
}
