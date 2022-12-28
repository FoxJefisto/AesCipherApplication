using aes;
using AesCipherApplication.Models;
using System;
using System.Collections.Generic;
using System.IO;
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
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace AesCipherApplication
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public KeyGenerator keyGenerator;
        public int dotIndex;
        public MainWindow()
        {
            InitializeComponent();
            keyGenerator = KeyGenerator.GetInstance();
        }

        private void RadioButton_Checked(object sender, RoutedEventArgs e)
        {
            var rb = e.Source as RadioButton;

            switch (rb.Content)
            {
                case "Файл":
                    tbText.Visibility = Visibility.Collapsed;
                    spInputPathFile.Visibility = Visibility.Visible;
                    spAction.Visibility = Visibility.Visible;
                    cbRemoveInputFile.Visibility = Visibility.Visible;
                    break;
                case "Текст":
                    spInputPathFile.Visibility = Visibility.Collapsed;
                    tbText.Visibility = Visibility.Visible;
                    spAction.Visibility = Visibility.Visible;
                    cbRemoveInputFile.Visibility = Visibility.Collapsed;
                    break;
                case "Зашифровать":
                    ChangeSuffixInFileName();
                    spExtra.Visibility = Visibility.Visible;
                    btnStart.Visibility = Visibility.Visible;
                    break;
                case "Расшифровать":
                    ChangeSuffixInFileName();
                    spExtra.Visibility = Visibility.Visible;
                    btnStart.Visibility = Visibility.Visible;
                    break;
                default:
                    break;
            }
        }

        private void btnInputPathFile_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.OpenFileDialog())
            {
                var result = dialog.ShowDialog();
                if (result == System.Windows.Forms.DialogResult.OK)
                {
                    tbInputPathFile.Text = dialog.FileName;
                }
            }
            dotIndex = tbInputPathFile.Text.LastIndexOf('.');
            ChangeSuffixInFileName();
        }

        private void btnStart_Click(object sender, RoutedEventArgs e)
        {
            if (keyGenerator.Key is null)
            {
                MessageBox.Show("Пароль не установлен", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                var crypter = new Crypter(keyGenerator.Key);
                if (rbEncrypt.IsChecked.Value)
                {
                    var passwordConfirmationWindow = new PasswordConfirmationWindow(pbPassword.Password);
                    passwordConfirmationWindow.Owner = this;
                    if (passwordConfirmationWindow.ShowDialog().Value)
                    {
                        if (rbText.IsChecked.Value)
                        {
                            if (cbSaveOutputInFile.IsChecked.Value)
                            {
                                tbResult.Visibility = Visibility.Collapsed;
                                File.WriteAllBytes(tbOutputPathFile.Text, crypter.EncryptStringToBytes(tbText.Text));
                            }
                            else
                            {
                                tbResult.Visibility = Visibility.Visible;
                                tbResult.Text = crypter.EncryptStringToString(tbText.Text);
                            }
                            
                        }
                        else if (rbFile.IsChecked.Value && File.Exists(tbInputPathFile.Text))
                        {
                            if (cbSaveOutputInFile.IsChecked.Value)
                            {
                                tbResult.Visibility = Visibility.Collapsed;
                                File.WriteAllBytes(tbOutputPathFile.Text, crypter.EncryptBytesToBytes(File.ReadAllBytes(tbInputPathFile.Text)));
                            }
                            else
                            {
                                tbResult.Visibility = Visibility.Visible;
                                tbResult.Text = crypter.EncryptBytesToString(File.ReadAllBytes(tbInputPathFile.Text));
                            }
                            if (cbRemoveInputFile.IsChecked.Value && tbInputPathFile.Text != tbOutputPathFile.Text)
                            {
                                File.Delete(tbInputPathFile.Text);
                            }
                            MessageBox.Show("Операция успешно выполнена", "SUCCESS", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                        else
                        {
                            MessageBox.Show("Неверно указаны пути к файлам", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                        
                    }
                    else
                    {
                        MessageBox.Show("При подтверждении пароли не совпали", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                else if (rbDecrypt.IsChecked.Value)
                {
                    if (rbText.IsChecked.Value)
                    {
                        if (cbSaveOutputInFile.IsChecked.Value)
                        {
                            tbResult.Visibility = Visibility.Collapsed;
                            File.WriteAllBytes(tbOutputPathFile.Text, crypter.DecryptStringToBytes(tbText.Text));
                        }
                        else
                        {
                            tbResult.Visibility = Visibility.Visible;
                            tbResult.Text = crypter.DecryptStringToString(tbText.Text);
                        }
                        
                    }
                    else if (rbFile.IsChecked.Value && File.Exists(tbInputPathFile.Text))
                    {
                        if (cbSaveOutputInFile.IsChecked.Value)
                        {
                            tbResult.Visibility = Visibility.Collapsed;
                            File.WriteAllBytes(tbOutputPathFile.Text, crypter.DecryptBytesToBytes(File.ReadAllBytes(tbInputPathFile.Text)));
                        }
                        else
                        {
                            tbResult.Visibility = Visibility.Visible;
                            tbResult.Text = crypter.DecryptBytesToString(File.ReadAllBytes(tbInputPathFile.Text));
                        }
                        if (cbRemoveInputFile.IsChecked.Value && tbInputPathFile.Text != tbOutputPathFile.Text)
                        {
                            File.Delete(tbInputPathFile.Text);
                        }
                        MessageBox.Show("Операция успешно выполнена", "SUCCESS", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show("Неверно указаны пути к файлам", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    
                }
            }
        }

        private void btnOutputPathFile_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.SaveFileDialog())
            {
                dialog.FileName = "Output"; // Default file name
                dialog.InitialDirectory = Path.GetDirectoryName(tbInputPathFile.Text);
                dialog.DefaultExt = ".txt"; // Default file extension
                var result = dialog.ShowDialog();
                if (result == System.Windows.Forms.DialogResult.OK)
                {
                    tbOutputPathFile.Text = dialog.FileName;
                }
            }
        }

        private void cbSaveOutputInFile_Checked(object sender, RoutedEventArgs e)
        {
            spOutputPathFile.Visibility = Visibility.Visible;
        }

        private void cbSaveOutputInFile_Unchecked(object sender, RoutedEventArgs e)
        {
            spOutputPathFile.Visibility = Visibility.Hidden;
        }

        private void btnPasswordSettings_Click(object sender, RoutedEventArgs e)
        {
            var passwordSettingsWindow = new PasswordSettingsWindow();
            passwordSettingsWindow.Owner = this;
            passwordSettingsWindow.ShowDialog();
        }

        private void btnPasswordSet_Click(object sender, RoutedEventArgs e)
        {
            if (keyGenerator.CreateKey(pbPassword.Password))
            {
                var passwordConfirmationWindow = new PasswordConfirmationWindow(pbPassword.Password);
                passwordConfirmationWindow.Owner = this;
                if (passwordConfirmationWindow.ShowDialog().Value)
                {
                    MessageBox.Show("Пароль успешно установлен", "SUCCESS", MessageBoxButton.OK, MessageBoxImage.Information);
                    PasswordSetCollapsed();
                    
                }
                else
                {
                    keyGenerator.Key = null;
                    MessageBox.Show("При подтверждении пароли не совпали", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                MessageBox.Show("Пароль не удовлетворяет требованиям", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnKeyChange_Click(object sender, RoutedEventArgs e)
        {
            keyGenerator.Key = null;
            PasswordSetVisible();
        }

        public void PasswordSetVisible()
        {
            pbPassword.Password = "";
            btnPasswordSet.Visibility = Visibility.Visible;
            pbPassword.Visibility = Visibility.Visible;
            btnPasswordChange.Visibility = Visibility.Collapsed;
        }

        public void PasswordSetCollapsed()
        {
            btnPasswordSet.Visibility = Visibility.Collapsed;
            pbPassword.Visibility = Visibility.Collapsed;
            btnPasswordChange.Visibility = Visibility.Visible;
            gbChoice.Visibility = Visibility.Visible;
        }

        private void cbRemoveInputFile_Checked(object sender, RoutedEventArgs e)
        {
            ChangeSuffixInFileName();
        }

        private void cbRemoveInputFile_Unchecked(object sender, RoutedEventArgs e)
        {
            ChangeSuffixInFileName();
        }

        private void ChangeSuffixInFileName()
        {
            var newDotIndex = tbInputPathFile.Text.LastIndexOf('.');
            if(newDotIndex != -1)
            {
                if (cbRemoveInputFile.IsChecked.Value)
                {
                    tbOutputPathFile.Text = tbInputPathFile.Text.Remove(dotIndex, newDotIndex - dotIndex);
                }
                else
                {
                    if (rbEncrypt.IsChecked.Value && rbFile.IsChecked.Value)
                    {
                        tbOutputPathFile.Text = tbInputPathFile.Text.Remove(dotIndex, newDotIndex - dotIndex);
                        tbOutputPathFile.Text = tbInputPathFile.Text.Insert(dotIndex, "[ENCRYPTED]");
                    }
                    else if (rbDecrypt.IsChecked.Value && rbFile.IsChecked.Value)
                    {
                        tbOutputPathFile.Text = tbInputPathFile.Text.Remove(dotIndex, newDotIndex - dotIndex);
                        tbOutputPathFile.Text = tbInputPathFile.Text.Insert(dotIndex, "[DECRYPTED]");
                    }
                }
            }
        }

        private void HelpCommand_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            var aboutWindow = new AboutWindow();
            aboutWindow.Owner = this;
            aboutWindow.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            aboutWindow.ShowDialog();
        }

        private void CloseCommand_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        
    }
}
