import { render } from 'nunjucks';
import { join } from 'path';

/**
 * @internal
 * Converts basic inline markdown formatting (urls, bold and italic) with
 * regular expressions.
 * Note that they must be greedy (*?) to format the markdown correctly.
 * @param text the markdown text to process
 */
function processMarkdown(text: string) {
  return text
    .replace(/(\s)\*\*(.*?)\*\*(\s)/gim, '$1<b>$2</b>$3')
    .replace(/(\s)\_(.*?)\_(\s)/gim, '$1<i>$2</i>$3')
    .replace(
      /\[(.*?)\]\((.*?)\)/gim,
      '<a style="text-decoration: underline; color: #193b92" href="$2">$1</a>'
    )
    .replace(/(\s)\*(.*?)\*(\s)/gim, '$1<i>$2</i>$3');
}

/**
 * @internal
 * Combines a base html template and the content, returning both a html and
 * plain text version of the email
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
