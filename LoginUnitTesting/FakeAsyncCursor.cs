using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LoginUnitTesting
{
    public class FakeAsyncCursor<T> : IAsyncCursor<T>
    {
        private readonly List<T> _items;
        private int _index = -1;

        public FakeAsyncCursor(List<T> items)
        {
            _items = items;
        }

        public IEnumerable<T> Current => _index >= 0 && _index < _items.Count ? new List<T> { _items[_index] } : new List<T>();

        public bool MoveNext(CancellationToken cancellationToken = default)
        {
            _index++;
            return _index < _items.Count;
        }

        public Task<bool> MoveNextAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(MoveNext(cancellationToken));
        }

        public void Dispose() { }
    }
}
