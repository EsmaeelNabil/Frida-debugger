export class ErrorHandler {
    static handle(error: Error, context: string): Error {
        const timestamp = new Date().toISOString();
        console.error(`[${timestamp}] [${context}] Error:`, error);

        let userMessage: string;
        if (error.message.includes('device not found')) {
            userMessage = 'Device connection lost. Please reconnect.';
        } else if (error.message.includes('process not found')) {
            userMessage = 'Application process terminated unexpectedly.';
        } else if (error.message.includes('timeout')) {
            userMessage = 'Operation timed out. Please try again.';
        } else {
            userMessage = 'An unexpected error occurred. Please try again.';
        }

        return new Error(userMessage);
    }
}