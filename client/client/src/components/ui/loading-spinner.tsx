import { cn } from "@/lib/utils"

interface LoadingSpinnerProps {
    className?: string
}

export function LoadingSpinner({ className }: LoadingSpinnerProps) {
    return (
        <div className="flex items-center justify-center h-screen bg-background">
            <div className={cn(
                "animate-spin rounded-full h-12 w-12 border-b-2 border-primary",
                className
            )} />
        </div>
    )
}