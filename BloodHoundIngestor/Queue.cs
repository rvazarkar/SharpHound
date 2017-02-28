using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace BloodHoundIngestor
{
    public class EnumerationQueue<T>
    {
        static ReaderWriterLockSlim _rw = new ReaderWriterLockSlim();
        static Queue<T> queue = new Queue<T>();

        public T get()
        {
            _rw.EnterReadLock();
            T item;
            try
            {
                item = queue.Dequeue();
                return item;
            }
            finally
            {
                _rw.ExitReadLock();
            }
        }

        public void add(T item)
        {
            _rw.EnterWriteLock();
            try
            {
                queue.Enqueue(item);
            }
            finally
            {
                _rw.ExitWriteLock();
            }
        }

        public int Count {
            get
            {
                return queue.Count;
            }
            set
            {

            }
        }
    }
}
