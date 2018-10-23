using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DZ2zad1
{
    class SimpleCommand:BaseCommand
    {
        private Action execute;
        private Predicate<object> predicate;

        public SimpleCommand(Action ex, Predicate<object> pred=null)
        {
            this.execute = ex ?? throw new ArgumentException(nameof(execute));
            this.predicate = pred;
        }
        public override bool CanExecute(object parameter)
        {
            return predicate?.Invoke(parameter) ?? true;
        }

        public override void Execute(object parameter)
        {
            execute();
        }
    }
}
