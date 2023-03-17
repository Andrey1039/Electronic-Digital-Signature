using System;
using System.Windows;
using System.Numerics;
using DigitalSignature.Data;
using DigitalSignature.Signature;

namespace DigitalSignature
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Signature()
        {
            BigInteger p = BigInteger.Parse(
                "57896044618658097711785492504343953926634992332820282019728792003956564821041");
            BigInteger a = BigInteger.Parse("7");
            BigInteger b = BigInteger.Parse(
                "43308876546767276905765904595650931995942111794451039583252968842033849580414");
            BigInteger q = BigInteger.Parse(
                "57896044618658097711785492504343953927082934583725450622380973592137631069619");
            BigInteger xP = BigInteger.Parse("2");
            BigInteger yP = BigInteger.Parse(
                "4018974056539037503335449422937059775635739389905545080690979365213431566280");

            // Создание ЭЦП
            EllipticPoint point = new EllipticPoint(a, b, p, xP, yP);
            DigSignature genSignature = new DigSignature(point, q);

            BigInteger d = genSignature.GeneratePrivateKey(32);
            EllipticPoint pointQ = genSignature.GeneratePublicKey(d);

            SignatureTB.Text = Convert.ToHexString(genSignature.GetSignature(InputTextTB.Text, d));

            point = new EllipticPoint(a, b, p, xP, yP);
            DigSignature checkSignature = new DigSignature(point, q);

            if (checkSignature.CheckSignature(InputText2TB.Text, Convert.FromHexString(SignatureTB.Text), pointQ))
                MessageBox.Show("Проверка пройдена!");
            else
                MessageBox.Show("Проверка провалена!");
        }

        private void ExecuteBtn_Click(object sender, RoutedEventArgs e)
        {
            Signature();
        }

        private void VerificationBtn_Click(object sender, RoutedEventArgs e)
        {
            Signature();
        }

        private void InputTextTB_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (!InputTextTB.Text.Equals(string.Empty) && !InputText2TB.Text.Equals(string.Empty))
                ExecuteBtn.IsEnabled = true;
            else
                ExecuteBtn.IsEnabled = false;
        }
    }
}
