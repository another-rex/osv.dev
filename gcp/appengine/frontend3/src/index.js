import './styles.scss';
import '@github/clipboard-copy-element';
import '@github/time-elements';
import '@material/mwc-circular-progress';
import '@material/mwc-icon';
import '@material/mwc-icon-button';
import '@hotwired/turbo';
import 'spicy-sections/src/SpicySections';
import {TextField as MwcTextField} from '@material/mwc-textfield';
import {LitElement, html, css, unsafeCSS} from 'lit';
import {unsafeHTML} from 'lit/directives/unsafe-html.js';
import hljs from 'highlight.js';
// TODO: raw-loader is deprecated.
import hljsStyles from '!!raw-loader!highlight.js/styles/github-dark.css';

import { throttle } from "throttle-debounce";

const queryField = document.querySelector('.query-field');
if (queryField) { // If we are in the list page
  const searchForm = document.querySelector('#search-form');
  const querySearchBtn = document.querySelector('#query-search-btn');
  const queryAutocompleteForm = document.querySelector('#autocomplete_btn');
  const queryAutocompleteField = document.querySelector('#autocomplete_input');

  const throttled_query_submit = throttle(500, () => {
    queryAutocompleteField.value = queryField.value;
    if (queryAutocompleteField.value.length < 2) {
      hideSearchBox();
      return;
    }

    queryAutocompleteForm.click();
  });
  queryField.addEventListener('input', (ev) => {
    throttled_query_submit();
  });

  searchForm.addEventListener('submit', () => {
    hideSearchBox();
  });

  function hideSearchBox() {
    let box = document.querySelector('.search-result-box-inner');
    if (box) {
      box.classList.add('hidden');
    }
  }

  window.autocompleteClick = function (autocompleteValue) {
    if (queryField) {
      queryField.value = autocompleteValue;
      querySearchBtn.click();
      hideSearchBox();
    }
  }
}

// Submits a form in a way such that Turbo can intercept the event.
// Triggering submit on the form directly would still give a correct resulting
// page, but we want to let Turbo speed up renders as intended.
const submitForm = function(form) {
  if (!form) {
    return;
  }
  const fakeSubmit = document.createElement('input');
  fakeSubmit.type = 'submit';
  fakeSubmit.style.display = 'none';
  form.appendChild(fakeSubmit);
  fakeSubmit.click();
  fakeSubmit.remove();
}

// A wrapper around <input type=radio> elements that submits their parent form
// when any radio item changes.
export class SubmitRadiosOnClickContainer extends LitElement {
  constructor() {
    super();
    this.addEventListener('change', () => submitForm(this.closest('form')))
  }
  // Render the contents of the element as-is.
  render() { return html`<slot></slot>`; }
}
customElements.define('submit-radios', SubmitRadiosOnClickContainer);

// A wrapper around <mwc-textfield> that adds back native-like enter key form
// submission behavior.
export class MwcTextFieldWithEnter extends MwcTextField {
  constructor() {
    super();
    this.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') {
        submitForm(this.closest('form'));
      }
    });
  }
}
customElements.define('mwc-textfield-with-enter', MwcTextFieldWithEnter);

export class CodeBlock extends LitElement {
  static get styles() {
    return [
      css`${unsafeCSS(hljsStyles)}`,
      css`:host pre {
        font-family: inherit;
        background: #333;
        border-radius: 10px;
        display: block;
        overflow: auto;
        padding: 10px;
      }`];
  }
  render() {
    const highlighted = hljs.highlightAuto(this.innerHTML).value;
    return html`<pre>${unsafeHTML(highlighted)}</pre>`;
  }
}
customElements.define('code-block', CodeBlock);
