import { Component } from 'react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert.jsx';

export default class ErrorBoundary extends Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('Error caught by boundary:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="p-4">
                    <Alert variant="destructive">
                        <AlertTitle>Something went wrong</AlertTitle>
                        <AlertDescription>
                            {this.state.error?.message || 'An unexpected error occurred'}
                        </AlertDescription>
                    </Alert>
                </div>
            );
        }

        return this.props.children;
    }
}