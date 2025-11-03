use std::rc::Rc;
use std::cell::RefCell;
use litesvm::LiteSVM;

pub struct SystemProgramBuilder {
    pub(crate) svm: Rc<RefCell<LiteSVM>>,
}

impl SystemProgramBuilder {
    // TODO: Implement system program methods like:
    // - transfer()
    // - create_account()
    // - allocate()
    // etc.
}
