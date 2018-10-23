using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DZ2zad1
{
    class AsyncCommand:BaseCommand
    {
        private Action<object> execute;
        private AsyncCallback callback;
        private Predicate<object> canExecute;

        public AsyncCommand(Action<object> ex, AsyncCallback cal = null, Predicate<object> can = null)
        {
            this.execute=ex;
            this.callback = cal;
            this.canExecute = can;
        }
        public override bool CanExecute(object parameter)
        {
            return canExecute == null || canExecute(parameter);
        }

        public override void Execute(object parameter)
        {
            execute.BeginInvoke(parameter, callback, null);
        }
    }
}
