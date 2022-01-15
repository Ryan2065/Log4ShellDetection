using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.CommandLine;

namespace Log4ShellDetection
{
    internal class CommandOptions
    {
        
        public RootCommand GetRootCommand()
        {


            return cmd;
        }

        public void RunCommand(string[]? paths = null)
        {

        }
    }
}
