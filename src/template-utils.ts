import { render } from 'nunjucks';
import { join } from 'path';

/**
 * Converts basic inline markdown formatting (urls, bold and italic) with
 * regular expressions.
 * Note that they must be greedy (*?) to format the markdown correctly.
 * @param text the markdown text to process
 */
function processMarkdown(text: string) {
  return text
    .replaceAll(/\*\*(.*?)\*\*/gim, '<b>$1</b>')
    .replaceAll(/\_(.*?)\_/gim, '<i>$1</i>')
    .replaceAll(
      /\[(.*?)\]\((.*?)\)/gim,
      '<a style="text-decoration: underline; color: #193b92" href="$2">$1</a>'
    )
    .replaceAll(/\*(.*?)\*/gim, '<i>$1</i>');
}

/**
 *
 * @param folderPath template directory
 * @param template plain text template whose paragraphs will be formatted into the base template. `.njk` gets appended.
 * @param data data that should be passed to the template.
 * @param base the base template. Default: `base.njk`
 * @returns
 */
export function parseCompositeTemplate(
  folderPath: string,
  template: string,
  data: Record<string, any> = {},
  base = 'base.njk'
) {
  const baseTemplate = join(folderPath, base);
  const contentPath = join(folderPath, `${template}.njk`);
  const plainTextContent = render(contentPath, data);
  const contentParagraphs = processMarkdown(plainTextContent).split('\n');
  data.paragraphs = contentParagraphs;
  data.year = new Date().getFullYear();

  return { html: render(baseTemplate, data), text: plainTextContent };
}

/**
 * Fallback method: If the `${template}.njk` is not present, this will be called
 * to directly render the html (`${template}.html.njk`) and plain text
 * (`${template}.text.njk`) templates without additional logic.
 */
export function parseTemplatesDirectly(
  folderPath: string,
  template: string,
  data: Record<string, any> = {}
) {
  let html;
  try {
    html = render(join(folderPath, `${template}.html.njk`), data);
  } catch (error) {}
  let text;
  try {
    text = render(join(folderPath, `${template}.text.njk`), data);
  } catch (error) {}
  return { html, text };
}
