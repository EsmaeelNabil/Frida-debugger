import * as fs from 'fs';
import * as path from 'path';


export class FilesManager {

    async readJSFiles(directoryPath: string, callback: (fileMap: Map<string, string>) => void) {
        try {
            const fileMap = new Map<string, string>();
            await this.readDirectoryRecursive(directoryPath, fileMap);
            callback(fileMap);
        } catch (error) {
            console.error('Error reading JS files:', error);
        }
    }

    async readDirectoryRecursive(directoryPath: string, fileMap: Map<string, string>) {
        try {
            const files = await this.readDirectory(directoryPath);

            // Filter only subdirectories
            const subdirectories = files.filter(file => !this.hasJSExtension(file));

            // Process files in the current directory
            const jsFiles = files.filter(file => this.hasJSExtension(file));
            await Promise.all(jsFiles.map(async file => {
                const filePath = path.join(directoryPath, file);
                const fileContent = await this.readFileContent(filePath);
                const fileNameWithoutExtension = path.parse(file).name;
                fileMap.set(fileNameWithoutExtension, fileContent);
            }));

            // Process subdirectories recursively
            await Promise.all(subdirectories.map(async subdirectory => {
                const subdirectoryPath = path.join(directoryPath, subdirectory);

                // Check if the item is a directory before processing
                const isDirectory = await this.isDirectory(subdirectoryPath);
                if (isDirectory) {
                    await this.readDirectoryRecursive(subdirectoryPath, fileMap);
                }
            }));
        } catch (error) {
            console.error('Error reading directory:', error);
        }
    }


    async readDirectory(directoryPath: string): Promise<string[]> {
        return new Promise((resolve, reject) => {
            fs.readdir(directoryPath, (err, files) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(files);
                }
            });
        });
    }

    async isDirectory(filePath: string): Promise<boolean> {
        return new Promise((resolve, reject) => {
            fs.stat(filePath, (err, stats) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(stats.isDirectory());
                }
            });
        });
    }

    async readFileContent(filePath: string): Promise<string> {
        return new Promise((resolve, reject) => {
            fs.readFile(filePath, 'utf8', (err, content) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(content);
                }
            });
        });
    }

    hasJSExtension(file: string): boolean {
        return path.extname(file) === '.js';
    }
}

/*

// Example usage
const directoryPath = '/path/to/your/directory';
const fileReader = new FilesManager();

fileReader.readJSFiles(directoryPath, (fileMap) => {
    // Handle the file map here
    console.log('File Map:', fileMap);
});
*/
