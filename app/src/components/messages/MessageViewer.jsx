import { useState, useEffect, useCallback } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area.jsx';
import { Input } from '@/components/ui/input.jsx';
import { Button } from '@/components/ui/button.jsx';
import { Search, Trash2 } from 'lucide-react';

export default function MessageViewer({ messages = [], onClear }) {
    const [searchQuery, setSearchQuery] = useState('');
    const [filteredMessages, setFilteredMessages] = useState(messages);

    useEffect(() => {
        if (!searchQuery) {
            setFilteredMessages(messages);
            return;
        }

        const filtered = messages.filter(msg =>
            msg.toLowerCase().includes(searchQuery.toLowerCase())
        );
        setFilteredMessages(filtered);
    }, [messages, searchQuery]);

    const handleClear = useCallback(() => {
        onClear();
        setSearchQuery('');
    }, [onClear]);

    return (
        <div className="border rounded-lg bg-white p-4 space-y-4">
            <div className="flex items-center justify-between">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-gray-400" />
                    <Input
                        placeholder="Search messages..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8"
                    />
                </div>
                <Button
                    variant="outline"
                    onClick={handleClear}
                    className="ml-2"
                >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Clear
                </Button>
            </div>

            <ScrollArea className="h-[400px] border rounded-md bg-gray-50">
                {filteredMessages.length > 0 ? (
                    filteredMessages.map((message, index) => (
                        <div
                            key={index}
                            className="flex border-b last:border-0 hover:bg-gray-100"
                        >
                            <div className="p-2 text-gray-500 bg-gray-100 border-r text-right min-w-[50px]">
                                {index + 1}
                            </div>
                            <div className="p-2 whitespace-pre-wrap break-all flex-1">
                                {message}
                            </div>
                        </div>
                    ))
                ) : (
                    <div className="flex items-center justify-center h-full text-gray-500">
                        No messages to display
                    </div>
                )}
            </ScrollArea>
        </div>
    );
}