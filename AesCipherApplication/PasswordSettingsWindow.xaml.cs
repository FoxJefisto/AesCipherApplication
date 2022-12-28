using AesCipherApplication.Models;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace AesCipherApplication
{
    /// <summary>
    /// Логика взаимодействия для KeySettingsWindow.xaml
    /// </summary>
    public partial class PasswordSettingsWindow : Window
    {
        private KeyGenerator keyGenerator;
        CheckPassword oldCheck;
        public PasswordSettingsWindow()
        {
            keyGenerator = KeyGenerator.GetInstance();
            oldCheck = (CheckPassword) keyGenerator.Check.Clone();
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            spKeyMinLength.DataContext = keyGenerator.Check;
            spCheckKey.DataContext = keyGenerator.Check;
            switch (Crypter.CipherMode)
            {
                case CipherMode.CBC:
                    rbCBC.IsChecked = true;
                    break;
                case CipherMode.OFB:
                    rbOFB.IsChecked = true;
                    break;
                case CipherMode.CFB:
                    rbCFB.IsChecked = true;
                    break;
                case CipherMode.ECB:
                default:
                    rbECB.IsChecked = true;
                    break;
            }
        }

        private void sldrLengthKey_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            tbLengthKey.Text = (sender as Slider).Value.ToString();
        }

        private void tbLenghtKey_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            if (int.TryParse(e.Text, out int result))
            {
                e.Handled = result < 6 || result > 30;
            }
            else
            {
                e.Handled = true;
            }

        }

        private void btnSave_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }

        private void btnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private void Window_Closed(object sender, EventArgs e)
        {
            if (keyGenerator.Key != null && oldCheck != keyGenerator.Check)
            {
                keyGenerator.Key = null;
                MessageBox.Show("Текущий ключ был сброшен", "WARNING", MessageBoxButton.OK, MessageBoxImage.Warning);
                (this.Owner as MainWindow).PasswordSetVisible();
            }
        }

        private void rbECB_Checked(object sender, RoutedEventArgs e)
        {
            Crypter.CipherMode = CipherMode.ECB;
        }

        private void rbCBC_Checked(object sender, RoutedEventArgs e)
        {
            Crypter.CipherMode = CipherMode.CBC;
        }

        private void rbCFB_Checked(object sender, RoutedEventArgs e)
        {
            Crypter.CipherMode = CipherMode.CFB;
        }

        private void rbOFB_Checked(object sender, RoutedEventArgs e)
        {
            Crypter.CipherMode = CipherMode.OFB;
        }
    }
}
