import { useState } from 'react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Search, Trash2 } from 'lucide-react'

interface MessageViewerProps {
    messages: string[]
}

export function MessageViewer({ messages }: MessageViewerProps) {
    const [searchQuery, setSearchQuery] = useState('')

    const filteredMessages = messages.filter(message =>
        message.toLowerCase().includes(searchQuery.toLowerCase())
    )

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-4">
                <div className="relative flex-1">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search messages..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8"
                    />
                </div>
                <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSearchQuery('')}
                >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Clear
                </Button>
            </div>

            <ScrollArea className="h-[400px] border rounded-lg">
                {filteredMessages.length > 0 ? (
                    filteredMessages.map((message, index) => (
                        <div
                            key={index}
                            className="flex border-b last:border-0"
                        >
                            <div className="p-2 text-muted-foreground bg-muted border-r min-w-[50px] text-right">
                                {index + 1}
                            </div>
                            <div className="p-2 whitespace-pre-wrap break-all">
                                {message}
                            </div>
                        </div>
                    ))
                ) : (
                    <div className="flex items-center justify-center h-full text-muted-foreground">
                        No messages to display
                    </div>
                )}
            </ScrollArea>
        </div>
    )
}